import {isRedirect, type Cookies} from '@sveltejs/kit';
import {exportJWK, sign} from '@sourceregistry/node-jwt';
import {createHash, generateKeyPairSync} from 'node:crypto';
import {describe, expect, it, vi} from 'vitest';

import {createOIDC} from './index.js';
import {decodeOAuthState, serializeSignedCookie} from './utils.js';
import type {OIDCHandleLocals, OIDCSession, OIDCStateCookie, OIDCUserClaims} from './types.js';

const createCookies = (): Cookies =>
    ({
        get: vi.fn(() => undefined),
        getAll: vi.fn(() => []),
        set: vi.fn(),
        delete: vi.fn(),
        serialize: vi.fn()
    }) as unknown as Cookies;

const cookieSecret = 'test-cookie-secret-at-least-32-bytes';

async function createRsaSigner() {
    const {privateKey, publicKey} = generateKeyPairSync('rsa', {
        modulusLength: 2048
    });
    const jwk = exportJWK(publicKey);
    return {
        jwks: {keys: [{...jwk, kid: 'test-key', alg: 'RS256', use: 'sig'}]},
        sign: (claims: Record<string, unknown>, typ = 'JWT') =>
            Promise.resolve(sign(claims, privateKey, {alg: 'RS256', kid: 'test-key', typ}))
    };
}

const createCookiesWithSession = (session: OIDCSession): Cookies => {
    const value = serializeSignedCookie(session, cookieSecret);
    return {
        get: vi.fn((name: string) => (name === 'oidc_session' ? value : undefined)),
        getAll: vi.fn(() => []),
        set: vi.fn(),
        delete: vi.fn(),
        serialize: vi.fn()
    } as unknown as Cookies;
};

const createCookiesWithValues = (values: Record<string, string>): Cookies =>
    ({
        get: vi.fn((name: string) => values[name]),
        getAll: vi.fn(() => []),
        set: vi.fn(),
        delete: vi.fn(),
        serialize: vi.fn()
    }) as unknown as Cookies;

const createMutableCookies = (): Cookies => {
    const values = new Map<string, string>();
    return {
        get: vi.fn((name: string) => values.get(name)),
        getAll: vi.fn(() => [...values].map(([name, value]) => ({name, value}))),
        set: vi.fn((name: string, value: string) => { values.set(name, value); }),
        delete: vi.fn((name: string) => { values.delete(name); }),
        serialize: vi.fn()
    } as unknown as Cookies;
};

const createRequestContext = <TData>(session: OIDCSession, data: TData): OIDCHandleLocals<OIDCUserClaims, TData> => ({
    isAuthenticated: true,
    session,
    identity: session.identity,
    data,
    requireAuth: async () => session,
    clearSession: async () => undefined
});

describe('OIDC logout', () => {
    it('includes client_id when redirecting to the provider without a local session', async () => {
        const oidc = createOIDC({
            issuer: 'https://identity.example/realms/test',
            clientId: 'client-app',
            cookieSecret,
            endpoints: {
                issuer: 'https://identity.example/realms/test',
                authorization_endpoint: 'https://identity.example/authorize',
                token_endpoint: 'https://identity.example/token',
                end_session_endpoint: 'https://identity.example/logout'
            }
        });
        const handler = oidc.logoutHandler({
            postLogoutRedirectUri: '/signed-out'
        });
        const url = new URL('https://app.example/auth/logout');

        try {
            await handler({
                cookies: createCookies(),
                request: new Request(url, {method: 'POST'}),
                url
            } as never);
            expect.fail('Expected provider logout redirect');
        } catch (error) {
            expect(isRedirect(error)).toBe(true);
            const location = new URL((error as {location: string}).location);
            expect(location.origin + location.pathname).toBe('https://identity.example/logout');
            expect(location.searchParams.get('client_id')).toBe('client-app');
            expect(location.searchParams.get('post_logout_redirect_uri')).toBe('https://app.example/signed-out');
            expect(location.searchParams.has('id_token_hint')).toBe(false);
        }
    });

    it('clears the local session without fetching unavailable provider metadata', async () => {
        const fetchImpl = vi.fn(() => Promise.reject(new Error('provider unavailable')));
        const cookies = createCookiesWithSession({
            issuer: 'https://identity.example',
            clientId: 'client-app',
            sub: 'user-1',
            groups: [],
            idTokenClaims: {sub: 'user-1'},
            identity: {sub: 'user-1'},
            tokens: {accessToken: 'access', tokenType: 'Bearer', scope: ['openid']},
            createdAt: Math.floor(Date.now() / 1000),
            refreshedAt: Math.floor(Date.now() / 1000)
        });
        const oidc = createOIDC({
            issuer: 'https://identity.example',
            clientId: 'client-app',
            cookieSecret,
            fetch: fetchImpl
        });
        const url = new URL('https://app.example/auth/logout');

        await expect(
            oidc.logoutHandler({clearSessionOnly: true})({
                cookies,
                request: new Request(url, {method: 'POST'}),
                url
            } as never)
        ).rejects.toSatisfy(isRedirect);
        expect(cookies.delete).toHaveBeenCalledWith('oidc_session', expect.any(Object));
        expect(fetchImpl).not.toHaveBeenCalled();
    });
});

describe('OIDC metadata validation', () => {
    it('rejects non-HTTP protocol endpoints even in local development mode', async () => {
        const oidc = createOIDC({
            issuer: 'http://localhost:8080',
            clientId: 'client-app',
            cookieSecret,
            allowInsecureHttp: true,
            endpoints: {
                authorization_endpoint: 'javascript:alert(1)',
                token_endpoint: 'http://localhost:8080/token'
            }
        });

        await expect(oidc.getMetadata()).rejects.toMatchObject({
            body: {message: 'OIDC authorization_endpoint must use HTTP or HTTPS'}
        });
    });

    it('rejects discovery metadata for a different issuer', async () => {
        const fetchImpl = vi.fn(
            async () =>
                new Response(
                    JSON.stringify({
                        issuer: 'https://attacker.example',
                        authorization_endpoint: 'https://attacker.example/authorize',
                        token_endpoint: 'https://attacker.example/token',
                        jwks_uri: 'https://attacker.example/jwks'
                    })
                )
        );
        const oidc = createOIDC({
            issuer: 'https://identity.example',
            clientId: 'client-app',
            cookieSecret,
            fetch: fetchImpl
        });

        await expect(oidc.getMetadata()).rejects.toMatchObject({
            body: {
                message: 'OIDC discovery issuer does not match the configured issuer'
            }
        });
        expect(fetchImpl).toHaveBeenCalledTimes(1);
    });

    it('does not retry a non-transient (4xx) discovery response', async () => {
        const fetchImpl = vi.fn(async () => new Response('not found', {status: 404}));
        const oidc = createOIDC({
            issuer: 'https://identity.example',
            clientId: 'client-app',
            cookieSecret,
            fetch: fetchImpl,
            discoveryRetry: {attempts: 5, initialDelayMs: 5, maxDelayMs: 5}
        });

        await expect(oidc.getMetadata()).rejects.toMatchObject({status: 404});
        expect(fetchImpl).toHaveBeenCalledTimes(1);
    });

    it('retries a transient (503) discovery failure until the identity provider is ready, then caches the result', async () => {
        const validDocument = {
            issuer: 'https://identity.example',
            authorization_endpoint: 'https://identity.example/authorize',
            token_endpoint: 'https://identity.example/token',
            jwks_uri: 'https://identity.example/jwks'
        };
        const fetchImpl = vi
            .fn()
            .mockResolvedValueOnce(new Response('starting up', {status: 503}))
            .mockResolvedValueOnce(new Response('starting up', {status: 503}))
            .mockResolvedValueOnce(new Response(JSON.stringify(validDocument)));
        const oidc = createOIDC({
            issuer: 'https://identity.example',
            clientId: 'client-app',
            cookieSecret,
            fetch: fetchImpl,
            discoveryRetry: {attempts: 5, initialDelayMs: 5, maxDelayMs: 5}
        });

        const metadata = await oidc.getMetadata();
        expect(metadata.issuer).toBe('https://identity.example');
        expect(fetchImpl).toHaveBeenCalledTimes(3);

        // Cached document is reused on the next call; no additional fetch inside the refresh interval.
        await oidc.getMetadata();
        expect(fetchImpl).toHaveBeenCalledTimes(3);
    });

    it('gives up after the configured number of transient discovery failures', async () => {
        const fetchImpl = vi.fn(async () => new Response('unavailable', {status: 503}));
        const oidc = createOIDC({
            issuer: 'https://identity.example',
            clientId: 'client-app',
            cookieSecret,
            fetch: fetchImpl,
            discoveryRetry: {attempts: 3, initialDelayMs: 5, maxDelayMs: 5}
        });

        await expect(oidc.getMetadata()).rejects.toMatchObject({status: 503});
        expect(fetchImpl).toHaveBeenCalledTimes(3);
    });
});

describe('OIDC authorization-code flow', () => {
    it('exchanges a PKCE code, validates the ID token, and persists a readable session', async () => {
        const signer = await createRsaSigner();
        const now = Math.floor(Date.now() / 1000);
        const cookies = createMutableCookies();
        let nonce: string | null = null;
        let challenge: string | null = null;
        const fetchImpl = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
            const url = String(input);
            if (url.endsWith('/token')) {
                const body = init?.body as URLSearchParams;
                expect(body.get('grant_type')).toBe('authorization_code');
                expect(body.get('code')).toBe('test-code');
                expect(body.get('redirect_uri')).toBe('https://app.example/auth/callback');
                expect(createHash('sha256').update(body.get('code_verifier')!).digest('base64url')).toBe(challenge);
                return new Response(JSON.stringify({
                    access_token: 'access-token',
                    token_type: 'Bearer',
                    refresh_token: 'refresh-token',
                    expires_in: 3600,
                    id_token: await signer.sign({
                        iss: 'https://identity.example',
                        sub: 'user-1',
                        aud: 'client-app',
                        nonce,
                        iat: now,
                        exp: now + 3600
                    })
                }));
            }
            if (url.endsWith('/jwks')) return new Response(JSON.stringify(signer.jwks));
            if (url.endsWith('/userinfo')) return new Response(JSON.stringify({sub: 'user-1', name: 'A User'}));
            throw new Error(`Unexpected URL ${url}`);
        });
        const oidc = createOIDC({
            issuer: 'https://identity.example',
            clientId: 'client-app',
            cookieSecret,
            fetch: fetchImpl,
            endpoints: {
                authorization_endpoint: 'https://identity.example/authorize',
                token_endpoint: 'https://identity.example/token',
                jwks_uri: 'https://identity.example/jwks',
                userinfo_endpoint: 'https://identity.example/userinfo'
            }
        });
        const loginUrl = new URL('https://app.example/auth/login?returnTo=%2Fdashboard');
        let state: string | null = null;
        try {
            await oidc.loginHandler()({cookies, request: new Request(loginUrl), url: loginUrl} as never);
            expect.fail('Expected authorization redirect');
        } catch (err) {
            expect(isRedirect(err)).toBe(true);
            const authorizationUrl = new URL((err as {location: string}).location);
            state = authorizationUrl.searchParams.get('state');
            nonce = authorizationUrl.searchParams.get('nonce');
            challenge = authorizationUrl.searchParams.get('code_challenge');
            expect(authorizationUrl.searchParams.get('code_challenge_method')).toBe('S256');
        }

        const callbackUrl = new URL(`https://app.example/auth/callback?code=test-code&state=${encodeURIComponent(state!)}`);
        const result = await oidc.handleCallback({
            cookies,
            url: callbackUrl,
            request: new Request(callbackUrl),
            locals: {}
        });

        expect(result.returnTo).toBe('/dashboard');
        expect(result.session.identity).toMatchObject({sub: 'user-1', name: 'A User'});
        expect(result.session.tokens.refreshToken).toBe('refresh-token');
        await expect(oidc.getSession({cookies})).resolves.toMatchObject({
            identity: {sub: 'user-1'},
            tokens: {accessToken: 'access-token'}
        });
    });

    it('retires the previous server session after a fresh login', async () => {
        const signer = await createRsaSigner();
        const now = Math.floor(Date.now() / 1000);
        const oldSession = {
            issuer: 'https://identity.example',
            clientId: 'client-app',
            sub: 'user-1',
            groups: [],
            idTokenClaims: {sub: 'user-1'},
            identity: {sub: 'user-1'},
            tokens: {accessToken: 'old-access', tokenType: 'Bearer', scope: ['openid']},
            createdAt: now - 60,
            refreshedAt: now - 60
        } satisfies OIDCSession;
        const sessions = new Map<string, OIDCSession>([['old-session', oldSession]]);
        const store = {
            get: async (id: string) => sessions.get(id) ?? null,
            set: async (id: string, value: OIDCSession) => { sessions.set(id, value); },
            delete: async (id: string) => { sessions.delete(id); }
        };
        const cookies = createMutableCookies();
        cookies.set('oidc_session', serializeSignedCookie({id: 'old-session'}, cookieSecret), {path: '/'});
        const oidc = createOIDC({
            issuer: oldSession.issuer,
            clientId: oldSession.clientId,
            cookieSecret,
            fetchUserInfo: false,
            fetch: async (input) => {
                if (String(input).endsWith('/jwks')) return new Response(JSON.stringify(signer.jwks));
                if (String(input).endsWith('/token')) {
                    return new Response(JSON.stringify({
                        access_token: 'new-access',
                        token_type: 'Bearer',
                        expires_in: 3600,
                        id_token: await signer.sign({
                            iss: oldSession.issuer,
                            sub: 'user-1',
                            aud: oldSession.clientId,
                            nonce: 'new-nonce',
                            iat: now,
                            exp: now + 3600
                        })
                    }));
                }
                throw new Error(`Unexpected URL ${String(input)}`);
            },
            sessionStore: store,
            endpoints: {
                authorization_endpoint: 'https://identity.example/authorize',
                token_endpoint: 'https://identity.example/token',
                jwks_uri: 'https://identity.example/jwks'
            }
        });
        const state = 'new-state';
        cookies.set(`oidc_auth_state.${state.slice(0, 16)}`, serializeSignedCookie({
            state,
            nonce: 'new-nonce',
            codeVerifier: 'new-verifier',
            returnTo: '/dashboard',
            createdAt: now
        }, cookieSecret), {path: '/'});
        const url = new URL(`https://app.example/auth/callback?code=new-code&state=${state}`);

        await oidc.handleCallback({cookies, url, request: new Request(url), locals: {}});

        expect(sessions.has('old-session')).toBe(false);
        expect(sessions.size).toBe(1);
        const newSession = await oidc.getSession({cookies});
        expect(newSession?.tokens.accessToken).toBe('new-access');
    });
});

describe('OIDC refresh validation and concurrency', () => {
    const expiredSession = () => {
        const now = Math.floor(Date.now() / 1000);
        return {
            issuer: 'https://identity.example',
            clientId: 'client-app',
            sub: 'user-1',
            groups: [],
            idTokenClaims: {sub: 'user-1'},
            identity: {sub: 'user-1'},
            tokens: {
                accessToken: 'old-access',
                tokenType: 'Bearer',
                refreshToken: 'old-refresh',
                scope: ['openid'],
                expiresAt: now - 1
            },
            createdAt: now - 60,
            refreshedAt: now - 60
        } satisfies OIDCSession;
    };
    const endpoints = {
        authorization_endpoint: 'https://identity.example/authorize',
        token_endpoint: 'https://identity.example/token'
    };

    it('keeps a still-valid access token when refresh has a transient server failure', async () => {
        const session = expiredSession();
        session.tokens.expiresAt = Math.floor(Date.now() / 1000) + 10;
        const cookies = createCookiesWithSession(session);
        const fetchImpl = vi.fn()
            .mockResolvedValueOnce(new Response('unavailable', {status: 503}))
            .mockResolvedValueOnce(new Response(JSON.stringify({
                access_token: 'new-access', token_type: 'Bearer', refresh_token: 'new-refresh', expires_in: 3600
            })));
        const oidc = createOIDC({
            issuer: session.issuer,
            clientId: session.clientId,
            cookieSecret,
            fetchUserInfo: false,
            fetch: fetchImpl,
            endpoints
        });

        await expect(oidc.getSession({cookies})).resolves.toMatchObject({tokens: {accessToken: 'old-access'}});
        expect(cookies.delete).not.toHaveBeenCalledWith('oidc_session', expect.any(Object));
        await expect(oidc.getSession({cookies})).resolves.toMatchObject({tokens: {refreshToken: 'new-refresh'}});
    });

    it('retains refresh credentials when the provider is temporarily down after access expiry', async () => {
        const session = expiredSession();
        const cookies = createCookiesWithSession(session);
        const fetchImpl = vi.fn()
            .mockResolvedValueOnce(new Response('unavailable', {status: 503}))
            .mockResolvedValueOnce(new Response(JSON.stringify({
                access_token: 'new-access', token_type: 'Bearer', refresh_token: 'new-refresh', expires_in: 3600
            })));
        const oidc = createOIDC({
            issuer: session.issuer,
            clientId: session.clientId,
            cookieSecret,
            fetchUserInfo: false,
            fetch: fetchImpl,
            endpoints
        });

        await expect(oidc.getSession({cookies})).rejects.toMatchObject({status: 503});
        expect(cookies.delete).not.toHaveBeenCalledWith('oidc_session', expect.any(Object));
        await expect(oidc.getSession({cookies})).resolves.toMatchObject({tokens: {refreshToken: 'new-refresh'}});
    });

    it('keeps a still-valid session when the distributed refresh lock is unavailable', async () => {
        const session = expiredSession();
        session.tokens.expiresAt = Math.floor(Date.now() / 1000) + 10;
        const sessions = new Map<string, OIDCSession>([['session-1', session]]);
        const store = {
            get: async (id: string) => sessions.get(id) ?? null,
            set: async (id: string, value: OIDCSession) => { sessions.set(id, value); },
            delete: async (id: string) => { sessions.delete(id); }
        };
        const fetchImpl = vi.fn();
        const oidc = createOIDC({
            issuer: session.issuer,
            clientId: session.clientId,
            cookieSecret,
            fetchUserInfo: false,
            fetch: fetchImpl,
            sessionStore: store,
            refreshLock: {runExclusive: async () => { throw new Error('lock unavailable'); }},
            endpoints
        });
        const cookies = createCookiesWithValues({
            oidc_session: serializeSignedCookie({id: 'session-1'}, cookieSecret)
        });

        await expect(oidc.getSession({cookies})).resolves.toMatchObject({tokens: {accessToken: 'old-access'}});
        expect(fetchImpl).not.toHaveBeenCalled();
        await expect(store.get('session-1')).resolves.not.toBeNull();
    });

    it('clears the session when the provider rejects its refresh token', async () => {
        const session = expiredSession();
        session.tokens.expiresAt = Math.floor(Date.now() / 1000) + 10;
        const cookies = createCookiesWithSession(session);
        const oidc = createOIDC({
            issuer: session.issuer,
            clientId: session.clientId,
            cookieSecret,
            fetchUserInfo: false,
            fetch: async () => new Response(JSON.stringify({error: 'invalid_grant'}), {status: 400}),
            endpoints
        });

        await expect(oidc.getSession({cookies})).resolves.toBeNull();
        expect(cookies.delete).toHaveBeenCalledWith('oidc_session', expect.any(Object));
    });

    it('preserves a rotated refresh token without carrying forward stale UserInfo claims', async () => {
        const session = {...expiredSession(), userInfo: {sub: 'user-1', name: 'Previous'}};
        const cookies = createCookiesWithSession(session);
        const fetchImpl = vi.fn(async (input: RequestInfo | URL) => {
            if (String(input).endsWith('/token')) {
                return new Response(JSON.stringify({
                    access_token: 'new-access', token_type: 'Bearer', refresh_token: 'new-refresh', expires_in: 3600
                }));
            }
            if (String(input).endsWith('/userinfo')) return new Response('unavailable', {status: 503});
            throw new Error(`Unexpected URL ${String(input)}`);
        });
        const oidc = createOIDC({
            issuer: session.issuer,
            clientId: session.clientId,
            cookieSecret,
            fetch: fetchImpl,
            endpoints: {...endpoints, userinfo_endpoint: 'https://identity.example/userinfo'}
        });

        const refreshed = await oidc.getSession({cookies});
        expect(refreshed?.tokens.refreshToken).toBe('new-refresh');
        expect(refreshed?.userInfo).toBeUndefined();
        expect(refreshed?.identity.name).toBeUndefined();
    });

    it('does not restore a server session removed while refresh was in flight', async () => {
        const session = expiredSession();
        const sessions = new Map<string, OIDCSession>([['session-1', session]]);
        const store = {
            get: vi.fn(async (id: string) => sessions.get(id) ?? null),
            set: vi.fn(async (id: string, value: OIDCSession) => { sessions.set(id, value); }),
            delete: vi.fn(async (id: string) => { sessions.delete(id); })
        };
        let releaseTokenResponse!: (response: Response) => void;
        const response = new Promise<Response>((resolve) => { releaseTokenResponse = resolve; });
        const fetchImpl = vi.fn(async () => response);
        const oidc = createOIDC({
            issuer: session.issuer,
            clientId: session.clientId,
            cookieSecret,
            fetchUserInfo: false,
            fetch: fetchImpl,
            sessionStore: store,
            endpoints
        });
        const cookies = createCookiesWithValues({
            oidc_session: serializeSignedCookie({id: 'session-1'}, cookieSecret)
        });

        const reading = oidc.getSession({cookies});
        await vi.waitFor(() => expect(fetchImpl).toHaveBeenCalledOnce());
        await store.delete('session-1');
        releaseTokenResponse(new Response(JSON.stringify({
            access_token: 'new-access', token_type: 'Bearer', refresh_token: 'new-refresh', expires_in: 3600
        })));

        await expect(reading).resolves.toBeNull();
        expect(store.set).not.toHaveBeenCalled();
    });

    it('does not restore a session when logout overlaps a delayed store write', async () => {
        const session = expiredSession();
        const sessions = new Map<string, OIDCSession>([['session-1', session]]);
        let completeWrite!: () => void;
        const writeReady = new Promise<void>((resolve) => { completeWrite = resolve; });
        const store = {
            get: vi.fn(async (id: string) => sessions.get(id) ?? null),
            set: vi.fn(async (id: string, value: OIDCSession) => {
                await writeReady;
                sessions.set(id, value);
            }),
            delete: vi.fn(async (id: string) => { sessions.delete(id); })
        };
        const oidc = createOIDC({
            issuer: session.issuer,
            clientId: session.clientId,
            cookieSecret,
            fetchUserInfo: false,
            fetch: async () => new Response(JSON.stringify({
                access_token: 'new-access', token_type: 'Bearer', refresh_token: 'new-refresh', expires_in: 3600
            })),
            sessionStore: store,
            endpoints
        });
        const cookies = createCookiesWithValues({
            oidc_session: serializeSignedCookie({id: 'session-1'}, cookieSecret)
        });

        const reading = oidc.getSession({cookies});
        await vi.waitFor(() => expect(store.set).toHaveBeenCalledOnce());
        await oidc.clearSession(cookies);
        completeWrite();

        await expect(reading).resolves.toBeNull();
        expect(sessions.has('session-1')).toBe(false);
    });

    it('does not return a session revoked while its refresh was in flight', async () => {
        const session = expiredSession();
        let revoked = false;
        let releaseTokenResponse!: (response: Response) => void;
        const response = new Promise<Response>((resolve) => { releaseTokenResponse = resolve; });
        const fetchImpl = vi.fn(async () => response);
        const cookies = createCookiesWithSession(session);
        const oidc = createOIDC({
            issuer: session.issuer,
            clientId: session.clientId,
            cookieSecret,
            fetchUserInfo: false,
            fetch: fetchImpl,
            backChannelLogoutStore: {revoke: () => undefined, isRevoked: () => revoked},
            endpoints
        });

        const reading = oidc.getSession({cookies});
        await vi.waitFor(() => expect(fetchImpl).toHaveBeenCalledOnce());
        revoked = true;
        releaseTokenResponse(new Response(JSON.stringify({
            access_token: 'new-access', token_type: 'Bearer', refresh_token: 'new-refresh', expires_in: 3600
        })));

        await expect(reading).resolves.toBeNull();
        expect(cookies.delete).toHaveBeenCalledWith('oidc_session', expect.any(Object));
    });

    it('uses the shared refresh lock to rotate once across two OIDC instances', async () => {
        const session = expiredSession();
        const sessions = new Map<string, OIDCSession>([['session-1', session]]);
        const store = {
            get: async (id: string) => sessions.get(id) ?? null,
            set: async (id: string, value: OIDCSession) => { sessions.set(id, value); },
            delete: async (id: string) => { sessions.delete(id); }
        };
        let previous = Promise.resolve();
        const refreshLock = {
            runExclusive: async <T>(_: string, task: () => Promise<T>): Promise<T> => {
                const wait = previous;
                let release!: () => void;
                previous = new Promise<void>((resolve) => { release = resolve; });
                await wait;
                try { return await task(); }
                finally { release(); }
            }
        };
        let tokenCalls = 0;
        const fetchImpl = vi.fn(async () => {
            tokenCalls++;
            return new Response(JSON.stringify({
                access_token: 'new-access', token_type: 'Bearer', refresh_token: 'new-refresh', expires_in: 3600
            }));
        });
        const options = {
            issuer: session.issuer,
            clientId: session.clientId,
            cookieSecret,
            fetchUserInfo: false,
            fetch: fetchImpl,
            sessionStore: store,
            refreshLock,
            endpoints
        };
        const first = createOIDC(options);
        const second = createOIDC(options);
        const cookieValue = serializeSignedCookie({id: 'session-1'}, cookieSecret);

        const [firstSession, secondSession] = await Promise.all([
            first.getSession({cookies: createCookiesWithValues({oidc_session: cookieValue})}),
            second.getSession({cookies: createCookiesWithValues({oidc_session: cookieValue})})
        ]);

        expect(tokenCalls).toBe(1);
        expect(firstSession?.tokens.refreshToken).toBe('new-refresh');
        expect(secondSession?.tokens.refreshToken).toBe('new-refresh');
    });

    it('serializes logout with refresh across instances using the shared lock', async () => {
        const session = expiredSession();
        const sessions = new Map<string, OIDCSession>([['session-1', session]]);
        let completeWrite!: () => void;
        const writeReady = new Promise<void>((resolve) => { completeWrite = resolve; });
        const store = {
            get: vi.fn(async (id: string) => sessions.get(id) ?? null),
            set: vi.fn(async (id: string, value: OIDCSession) => {
                await writeReady;
                sessions.set(id, value);
            }),
            delete: vi.fn(async (id: string) => { sessions.delete(id); })
        };
        let previous = Promise.resolve();
        const refreshLock = {
            runExclusive: async <T>(_: string, task: () => Promise<T>): Promise<T> => {
                const wait = previous;
                let release!: () => void;
                previous = new Promise<void>((resolve) => { release = resolve; });
                await wait;
                try { return await task(); }
                finally { release(); }
            }
        };
        const options = {
            issuer: session.issuer,
            clientId: session.clientId,
            cookieSecret,
            fetchUserInfo: false,
            fetch: async () => new Response(JSON.stringify({
                access_token: 'new-access', token_type: 'Bearer', refresh_token: 'new-refresh', expires_in: 3600
            })),
            sessionStore: store,
            refreshLock,
            endpoints
        };
        const first = createOIDC(options);
        const second = createOIDC(options);
        const cookies = createCookiesWithValues({
            oidc_session: serializeSignedCookie({id: 'session-1'}, cookieSecret)
        });

        const refreshing = first.getSession({cookies});
        await vi.waitFor(() => expect(store.set).toHaveBeenCalledOnce());
        const clearing = second.clearSession(cookies);
        await Promise.resolve();
        expect(store.delete).not.toHaveBeenCalled();

        completeWrite();
        await refreshing;
        await clearing;
        expect(sessions.has('session-1')).toBe(false);
        expect(store.delete).toHaveBeenCalledWith('session-1');
    });

    it('rejects a refresh response without a usable access token', async () => {
        const now = Math.floor(Date.now() / 1000);
        const session = {
            issuer: 'https://identity.example',
            clientId: 'client-app',
            sub: 'user-1',
            groups: [],
            idTokenClaims: {sub: 'user-1'},
            identity: {sub: 'user-1'},
            tokens: {
                accessToken: 'old-access',
                tokenType: 'Bearer',
                refreshToken: 'old-refresh',
                scope: ['openid'],
                expiresAt: now - 1
            },
            createdAt: now - 60,
            refreshedAt: now - 60
        } satisfies OIDCSession;
        const cookies = createCookiesWithSession(session);
        const oidc = createOIDC({
            issuer: session.issuer,
            clientId: session.clientId,
            cookieSecret,
            fetchUserInfo: false,
            fetch: async () => new Response(JSON.stringify({token_type: 'Bearer', expires_in: 3600})),
            endpoints: {
                authorization_endpoint: 'https://identity.example/authorize',
                token_endpoint: 'https://identity.example/token'
            }
        });

        await expect(oidc.getSession({cookies})).resolves.toBeNull();
        expect(cookies.delete).toHaveBeenCalledWith('oidc_session', expect.any(Object));
    });

    it.each([
        {token_type: 'DPoP', expires_in: 3600},
        {token_type: 'Bearer', expires_in: 0},
        {token_type: 'Bearer', expires_in: '3600'}
    ])('rejects an unusable refresh response: %j', async (fields) => {
        const session = expiredSession();
        const cookies = createCookiesWithSession(session);
        const oidc = createOIDC({
            issuer: session.issuer,
            clientId: session.clientId,
            cookieSecret,
            fetchUserInfo: false,
            fetch: async () => new Response(JSON.stringify({access_token: 'new-access', ...fields})),
            endpoints
        });

        await expect(oidc.getSession({cookies})).resolves.toBeNull();
        expect(cookies.delete).toHaveBeenCalledWith('oidc_session', expect.any(Object));
    });

    it('accepts a nonce-less conforming refresh and performs one rotating refresh for concurrent requests', async () => {
        const signer = await createRsaSigner();
        const now = Math.floor(Date.now() / 1000);
        const refreshedIdToken = await signer.sign({
            iss: 'https://identity.example',
            sub: 'user-1',
            aud: 'client-app',
            iat: now,
            exp: now + 3600
        });
        let tokenCalls = 0;
        const fetchImpl = vi.fn(async (input: RequestInfo | URL) => {
            const url = String(input);
            if (url.endsWith('/jwks')) return new Response(JSON.stringify(signer.jwks));
            if (url.endsWith('/token')) {
                tokenCalls += 1;
                await Promise.resolve();
                return new Response(
                    JSON.stringify({
                        access_token: 'new-access',
                        token_type: 'Bearer',
                        refresh_token: 'new-refresh',
                        expires_in: 3600,
                        id_token: refreshedIdToken
                    })
                );
            }
            throw new Error(`Unexpected URL ${url}`);
        });
        const session = {
            issuer: 'https://identity.example',
            clientId: 'client-app',
            nonce: 'original-nonce',
            sub: 'user-1',
            groups: [],
            idTokenClaims: {
                sub: 'user-1',
                iss: 'https://identity.example',
                aud: 'client-app',
                nonce: 'original-nonce',
                iat: now - 60,
                exp: now + 3600
            },
            identity: {sub: 'user-1'},
            tokens: {
                accessToken: 'old-access',
                tokenType: 'Bearer',
                refreshToken: 'old-refresh',
                scope: ['openid'],
                expiresAt: now - 1
            },
            createdAt: now - 60,
            refreshedAt: now - 60
        } satisfies OIDCSession;
        const oidc = createOIDC({
            issuer: session.issuer,
            clientId: session.clientId,
            cookieSecret,
            fetchUserInfo: false,
            fetch: fetchImpl,
            endpoints: {
                issuer: session.issuer,
                authorization_endpoint: 'https://identity.example/authorize',
                token_endpoint: 'https://identity.example/token',
                jwks_uri: 'https://identity.example/jwks',
                id_token_signing_alg_values_supported: ['RS256']
            }
        });

        const [first, second] = await Promise.all([
            oidc.getSession({cookies: createCookiesWithSession(session)}),
            oidc.getSession({cookies: createCookiesWithSession(session)})
        ]);

        expect(tokenCalls).toBe(1);
        expect(first?.tokens.refreshToken).toBe('new-refresh');
        expect(second?.sub).toBe('user-1');
    });
});

describe('OIDC back-channel logout validation', () => {
    it('accepts an explicitly typed logout token and records the revocation', async () => {
        const signer = await createRsaSigner();
        const now = Math.floor(Date.now() / 1000);
        const logoutToken = await signer.sign(
            {
                iss: 'https://identity.example',
                aud: 'client-app',
                sub: 'user-1',
                iat: now,
                exp: now + 60,
                jti: 'logout-1',
                events: {'http://schemas.openid.net/event/backchannel-logout': {}}
            },
            'logout+jwt'
        );
        const revoke = vi.fn();
        const oidc = createOIDC({
            issuer: 'https://identity.example',
            clientId: 'client-app',
            cookieSecret,
            backChannelLogoutStore: {revoke, isRevoked: () => false},
            fetch: async (input) => {
                if (String(input).endsWith('/jwks')) return new Response(JSON.stringify(signer.jwks));
                throw new Error(`Unexpected URL ${String(input)}`);
            },
            endpoints: {
                issuer: 'https://identity.example',
                authorization_endpoint: 'https://identity.example/authorize',
                token_endpoint: 'https://identity.example/token',
                jwks_uri: 'https://identity.example/jwks',
                id_token_signing_alg_values_supported: ['RS256'],
                backchannel_logout_supported: true
            }
        });
        const request = new Request('https://app.example/auth/backchannel-logout', {
            method: 'POST',
            body: new URLSearchParams({logout_token: logoutToken})
        });

        const response = await oidc.handleBackChannelLogout({request} as never);
        expect(response.status).toBe(200);
        expect(revoke).toHaveBeenCalledWith(expect.objectContaining({sub: 'user-1', jti: 'logout-1'}));
    });
});

describe('OIDC session-management re-authentication', () => {
    const session = {
        issuer: 'https://identity.example/realms/test',
        clientId: 'client-app',
        nonce: 'original-nonce',
        sub: 'user-1',
        groups: [],
        idTokenClaims: {sub: 'user-1'},
        identity: {sub: 'user-1'},
        tokens: {
            accessToken: 'access-token',
            tokenType: 'Bearer',
            idToken: 'original-id-token',
            scope: ['openid']
        },
        createdAt: Math.floor(Date.now() / 1000),
        refreshedAt: Math.floor(Date.now() / 1000)
    } satisfies OIDCSession;

    it('passes prompt=none and the current ID token hint to the authorization endpoint', async () => {
        const oidc = createOIDC({
            issuer: session.issuer,
            clientId: session.clientId,
            cookieSecret,
            endpoints: {
                issuer: session.issuer,
                authorization_endpoint: 'https://identity.example/authorize',
                token_endpoint: 'https://identity.example/token'
            }
        });
        const handler = oidc.loginHandler();
        const url = new URL('https://app.example/auth/login?prompt=none&returnTo=%2Fdashboard');

        try {
            await handler({
                cookies: createCookiesWithSession(session),
                request: new Request(url),
                url
            } as never);
            expect.fail('Expected authorization redirect');
        } catch (error) {
            expect(isRedirect(error)).toBe(true);
            const location = new URL((error as {location: string}).location);
            expect(location.searchParams.get('prompt')).toBe('none');
            expect(location.searchParams.get('id_token_hint')).toBe('original-id-token');
        }
    });

    it('clears the local session when prompt=none reports that the OP session is gone', async () => {
        const state = {
            state: 'silent-state',
            nonce: 'silent-nonce',
            codeVerifier: 'silent-verifier',
            returnTo: '/dashboard',
            prompt: 'none',
            originalSub: 'user-1',
            createdAt: Math.floor(Date.now() / 1000)
        } satisfies OIDCStateCookie;
        const cookies = createCookiesWithValues({
            oidc_session: serializeSignedCookie(session, cookieSecret),
            oidc_auth_state: serializeSignedCookie(state, cookieSecret)
        });
        const oidc = createOIDC({
            issuer: session.issuer,
            clientId: session.clientId,
            cookieSecret,
            endpoints: {
                issuer: session.issuer,
                authorization_endpoint: 'https://identity.example/authorize',
                token_endpoint: 'https://identity.example/token'
            }
        });
        const handler = oidc.callbackHandler();
        const url = new URL('https://app.example/auth/callback?error=login_required&state=silent-state');

        const response = await handler({
            cookies,
            request: new Request(url),
            url
        } as never);
        expect(response.status).toBe(200);
        expect(await response.text()).toContain('data-oidc-silent-reauth="logged_out"');
        expect(cookies.delete).toHaveBeenCalledWith('oidc_session', expect.any(Object));
        expect(cookies.delete).toHaveBeenCalledWith('oidc_auth_state', expect.any(Object));
    });

    it('preserves a newer local login when an older silent callback reports an OP error', async () => {
        const state = {
            state: 'silent-state',
            nonce: 'silent-nonce',
            codeVerifier: 'silent-verifier',
            returnTo: '/dashboard',
            prompt: 'none',
            originalSub: 'user-1',
            originalNonce: session.nonce,
            createdAt: Math.floor(Date.now() / 1000)
        } satisfies OIDCStateCookie;
        const newerSession = {...session, nonce: 'new-login-nonce'};
        const cookies = createCookiesWithValues({
            oidc_session: serializeSignedCookie(newerSession, cookieSecret),
            oidc_auth_state: serializeSignedCookie(state, cookieSecret)
        });
        const oidc = createOIDC({
            issuer: session.issuer,
            clientId: session.clientId,
            cookieSecret,
            endpoints: {
                issuer: session.issuer,
                authorization_endpoint: 'https://identity.example/authorize',
                token_endpoint: 'https://identity.example/token'
            }
        });
        const url = new URL('https://app.example/auth/callback?error=login_required&state=silent-state');

        const response = await oidc.callbackHandler()({cookies, request: new Request(url), url} as never);

        expect(await response.text()).toContain('data-oidc-silent-reauth="authenticated"');
        expect(cookies.delete).not.toHaveBeenCalledWith('oidc_session', expect.any(Object));
        await expect(oidc.getSession({cookies})).resolves.toMatchObject({nonce: 'new-login-nonce'});
    });

    it('retains the local session when silent re-authentication hits a temporary provider failure', async () => {
        const state = {
            state: 'silent-state',
            nonce: 'silent-nonce',
            codeVerifier: 'silent-verifier',
            returnTo: '/dashboard',
            prompt: 'none',
            originalSub: session.sub,
            originalNonce: session.nonce,
            createdAt: Math.floor(Date.now() / 1000)
        } satisfies OIDCStateCookie;
        const cookies = createCookiesWithValues({
            oidc_session: serializeSignedCookie(session, cookieSecret),
            oidc_auth_state: serializeSignedCookie(state, cookieSecret)
        });
        const oidc = createOIDC({
            issuer: session.issuer,
            clientId: session.clientId,
            cookieSecret,
            logger: false,
            fetch: vi.fn(async () => new Response('provider unavailable', {status: 503})),
            endpoints: {
                issuer: session.issuer,
                authorization_endpoint: 'https://identity.example/authorize',
                token_endpoint: 'https://identity.example/token'
            }
        });
        const url = new URL('https://app.example/auth/callback?code=silent-code&state=silent-state');

        const response = await oidc.callbackHandler()({cookies, request: new Request(url), url} as never);

        expect(await response.text()).toContain('data-oidc-silent-reauth="authenticated"');
        expect(cookies.delete).not.toHaveBeenCalledWith('oidc_session', expect.any(Object));
        await expect(oidc.getSession({cookies})).resolves.toMatchObject({sub: 'user-1'});
    });

    it('does not replace a newer local login when an older silent callback succeeds', async () => {
        const signer = await createRsaSigner();
        const now = Math.floor(Date.now() / 1000);
        const state = {
            state: 'silent-state',
            nonce: 'silent-nonce',
            codeVerifier: 'silent-verifier',
            returnTo: '/dashboard',
            prompt: 'none',
            originalSub: 'user-1',
            originalNonce: session.nonce,
            createdAt: now
        } satisfies OIDCStateCookie;
        const newerSession = {...session, nonce: 'new-login-nonce'};
        const cookies = createCookiesWithValues({
            oidc_session: serializeSignedCookie(newerSession, cookieSecret),
            oidc_auth_state: serializeSignedCookie(state, cookieSecret)
        });
        const fetchImpl = vi.fn(async (input: RequestInfo | URL) => {
            const url = String(input);
            if (url.endsWith('/token')) {
                return new Response(JSON.stringify({
                    access_token: 'silent-access-token',
                    token_type: 'Bearer',
                    id_token: await signer.sign({
                        iss: session.issuer,
                        sub: session.sub,
                        aud: session.clientId,
                        nonce: state.nonce,
                        iat: now,
                        exp: now + 3600
                    })
                }));
            }
            if (url.endsWith('/jwks')) return new Response(JSON.stringify(signer.jwks));
            throw new Error(`Unexpected URL ${url}`);
        });
        const oidc = createOIDC({
            issuer: session.issuer,
            clientId: session.clientId,
            cookieSecret,
            fetch: fetchImpl,
            fetchUserInfo: false,
            endpoints: {
                issuer: session.issuer,
                authorization_endpoint: 'https://identity.example/authorize',
                token_endpoint: 'https://identity.example/token',
                jwks_uri: 'https://identity.example/jwks'
            }
        });
        const url = new URL('https://app.example/auth/callback?code=silent-code&state=silent-state');

        const response = await oidc.callbackHandler()({cookies, request: new Request(url), url} as never);

        expect(await response.text()).toContain('data-oidc-silent-reauth="authenticated"');
        expect(cookies.set).not.toHaveBeenCalledWith('oidc_session', expect.anything(), expect.anything());
        expect(cookies.delete).not.toHaveBeenCalledWith('oidc_session', expect.any(Object));
        await expect(oidc.getSession({cookies})).resolves.toMatchObject({nonce: 'new-login-nonce'});
    });
});

describe('OIDC callback state recovery', () => {
    const endpoints = {
        issuer: 'https://identity.example/realms/test',
        authorization_endpoint: 'https://identity.example/authorize',
        token_endpoint: 'https://identity.example/token'
    };

    it('rejects a provider error unless its callback state matches the transaction', async () => {
        const oidc = createOIDC({
            issuer: endpoints.issuer,
            clientId: 'client-app',
            cookieSecret,
            endpoints
        });
        const url = new URL('https://app.example/auth/callback?error=access_denied&error_description=Denied&state=forged');

        await expect(oidc.handleCallback({cookies: createCookies(), url} as never)).rejects.toMatchObject({
            body: {message: 'Invalid or expired callback state'}
        });
    });

    it('preserves returnTo across a restart when the state cookie is missing', async () => {
        // Regression test: the state cookie carrying `returnTo` can go
        // missing before the browser gets back from the provider (past
        // stateMaxAgeSeconds, or overwritten by a second login started in
        // another tab) - restarting the login used to silently fall back to
        // defaultLoginRedirect in that case, discarding where the caller
        // actually wanted to end up.
        const oidc = createOIDC({
            issuer: endpoints.issuer,
            clientId: 'client-app',
            cookieSecret,
            endpoints
        });

        const loginUrl = new URL('https://app.example/auth/login?returnTo=%2Fadmin%2Fclients');
        let capturedState: string | null = null;

        try {
            await oidc.loginHandler()({
                cookies: createCookies(),
                request: new Request(loginUrl),
                url: loginUrl
            } as never);
            expect.fail('Expected an authorization redirect');
        } catch (err) {
            expect(isRedirect(err)).toBe(true);
            capturedState = new URL((err as {location: string}).location).searchParams.get('state');
        }
        expect(capturedState).toBeTruthy();

        // The browser comes back with `code`/`state` on the URL, but no
        // state cookie at all - `createCookies()` always reads as empty.
        const callbackUrl = new URL(
            `https://app.example/auth/callback?code=auth-code&state=${encodeURIComponent(capturedState!)}`
        );

        try {
            await oidc.handleCallback({
                cookies: createCookies(),
                url: callbackUrl
            } as never);
            expect.fail('Expected the login flow to restart');
        } catch (err) {
            expect(isRedirect(err)).toBe(true);
            const location = new URL((err as {location: string}).location);
            expect(location.origin + location.pathname).toBe('https://identity.example/authorize');

            const restartedState = location.searchParams.get('state');
            expect(restartedState).not.toBe(capturedState);
            expect(decodeOAuthState(restartedState, cookieSecret).returnTo).toBe('/admin/clients');
        }
    });

    it('falls back to defaultLoginRedirect only when no returnTo can be recovered at all', async () => {
        const oidc = createOIDC({
            issuer: endpoints.issuer,
            clientId: 'client-app',
            cookieSecret,
            defaultLoginRedirect: '/dashboard',
            endpoints
        });

        const callbackUrl = new URL('https://app.example/auth/callback?code=auth-code&state=not-a-real-state');

        try {
            await oidc.handleCallback({
                cookies: createCookies(),
                url: callbackUrl
            } as never);
            expect.fail('Expected the login flow to restart');
        } catch (err) {
            expect(isRedirect(err)).toBe(true);
            const location = new URL((err as {location: string}).location);
            expect(decodeOAuthState(location.searchParams.get('state'), cookieSecret).returnTo).toBe('/dashboard');
        }
    });
});

describe('OIDC public session revalidation', () => {
    it('registers a targeted SvelteKit dependency when depends is available', async () => {
        const oidc = createOIDC({
            issuer: 'https://identity.example/realms/test',
            clientId: 'client-app',
            cookieSecret,
            endpoints: {
                issuer: 'https://identity.example/realms/test',
                authorization_endpoint: 'https://identity.example/authorize',
                token_endpoint: 'https://identity.example/token'
            }
        });
        const depends = vi.fn();
        const url = new URL('https://app.example/');

        await oidc.getPublicSession({
            cookies: createCookies(),
            url,
            request: new Request(url),
            locals: {},
            depends
        });

        expect(depends).toHaveBeenCalledOnce();
        expect(depends).toHaveBeenCalledWith('oidc:session');
    });

    it('projects an already loaded request context without repeating server work', () => {
        const loadRequestData = vi.fn();
        const oidc = createOIDC({
            issuer: 'https://identity.example/realms/test',
            clientId: 'client-app',
            cookieSecret,
            endpoints: {
                issuer: 'https://identity.example/realms/test',
                authorization_endpoint: 'https://identity.example/authorize',
                token_endpoint: 'https://identity.example/token'
            },
            loadRequestData
        });
        const depends = vi.fn();
        const session = {
            issuer: 'https://identity.example/realms/test',
            clientId: 'client-app',
            sub: 'user-1',
            groups: ['admin'],
            idTokenClaims: {sub: 'user-1'},
            identity: {sub: 'user-1'},
            tokens: {accessToken: 'access', tokenType: 'Bearer', scope: ['openid']},
            createdAt: Math.floor(Date.now() / 1000),
            refreshedAt: Math.floor(Date.now() / 1000)
        } satisfies OIDCSession;

        const result = oidc.toPublicSession(createRequestContext(session, undefined), depends);

        expect(loadRequestData).not.toHaveBeenCalled();
        expect(depends).toHaveBeenCalledWith('oidc:session');
        expect(result).toMatchObject({
            isAuthenticated: true,
            sub: 'user-1',
            groups: ['admin'],
            revalidationDependency: 'oidc:session'
        });
    });

    it('creates an application public session from request-only data', () => {
        const createPublicSession = vi.fn(({base, data}) => ({
            ...base,
            identity: {...base.identity, permissions: data?.permissions ?? []}
        }));
        const oidc = createOIDC<OIDCUserClaims, {permissions: string[]}>({
            issuer: 'https://identity.example/realms/test',
            clientId: 'client-app',
            cookieSecret,
            endpoints: {
                issuer: 'https://identity.example/realms/test',
                authorization_endpoint: 'https://identity.example/authorize',
                token_endpoint: 'https://identity.example/token'
            },
            createPublicSession
        });
        const session = {
            issuer: 'https://identity.example/realms/test',
            clientId: 'client-app',
            sub: 'user-1',
            groups: [],
            idTokenClaims: {sub: 'user-1'},
            identity: {sub: 'user-1'},
            tokens: {accessToken: 'access', tokenType: 'Bearer', scope: ['openid']},
            createdAt: Math.floor(Date.now() / 1000),
            refreshedAt: Math.floor(Date.now() / 1000)
        } satisfies OIDCSession;

        const result = oidc.toPublicSession(createRequestContext(session, {permissions: ['read', 'write']}));

        expect(createPublicSession).toHaveBeenCalledOnce();
        expect(result?.identity).toEqual({
            sub: 'user-1',
            permissions: ['read', 'write']
        });
    });
});

describe('OIDC request data', () => {
    const baseSession = {
        issuer: 'https://identity.example/realms/test',
        clientId: 'client-app',
        groups: [],
        idTokenClaims: {sub: 'user-1'},
        identity: {sub: 'user-1'},
        tokens: {accessToken: 'access', tokenType: 'Bearer', scope: ['openid']},
        createdAt: Math.floor(Date.now() / 1000),
        refreshedAt: Math.floor(Date.now() / 1000)
    } satisfies OIDCSession;

    it('loads request data while building the request context', async () => {
        const loadRequestData = vi.fn(async () => ({permissions: ['read']}));
        const oidc = createOIDC({
            issuer: 'https://identity.example/realms/test',
            clientId: 'client-app',
            cookieSecret,
            endpoints: {
                issuer: 'https://identity.example/realms/test',
                authorization_endpoint: 'https://identity.example/authorize',
                token_endpoint: 'https://identity.example/token'
            },
            loadRequestData
        });

        const url = new URL('https://app.example/dashboard');
        const context = await oidc.createRequestContext({
            cookies: createCookiesWithSession(baseSession),
            url,
            request: new Request(url),
            locals: {}
        });

        expect(loadRequestData).toHaveBeenCalledOnce();
        expect(context.data).toEqual({permissions: ['read']});
    });

    it('does not load request data when there is no session', async () => {
        const loadRequestData = vi.fn();
        const oidc = createOIDC({
            issuer: 'https://identity.example/realms/test',
            clientId: 'client-app',
            cookieSecret,
            endpoints: {
                issuer: 'https://identity.example/realms/test',
                authorization_endpoint: 'https://identity.example/authorize',
                token_endpoint: 'https://identity.example/token'
            },
            loadRequestData
        });

        const url = new URL('https://app.example/dashboard');
        const context = await oidc.createRequestContext({
            cookies: createCookies(),
            url,
            request: new Request(url),
            locals: {}
        });

        expect(loadRequestData).not.toHaveBeenCalled();
        expect(context.data).toBeNull();
    });

    it('discards sessions created with the previous session shape', async () => {
        const oldSession = {
            issuer: baseSession.issuer,
            clientId: baseSession.clientId,
            groups: [],
            tokens: baseSession.tokens,
            createdAt: baseSession.createdAt,
            refreshedAt: baseSession.refreshedAt
        };
        const cookies = createCookiesWithSession(oldSession as unknown as OIDCSession);
        const oidc = createOIDC({
            issuer: 'https://identity.example/realms/test',
            clientId: 'client-app',
            cookieSecret,
            endpoints: {
                issuer: 'https://identity.example/realms/test',
                authorization_endpoint: 'https://identity.example/authorize',
                token_endpoint: 'https://identity.example/token'
            }
        });

        await expect(oidc.getSession({cookies})).resolves.toBeNull();
        expect(cookies.delete).toHaveBeenCalledWith('oidc_session', expect.any(Object));
    });

    it('does not accept a session issued for another client or issuer', async () => {
        const oidc = createOIDC({
            issuer: baseSession.issuer,
            clientId: 'client-app',
            cookieSecret
        });
        for (const foreignSession of [
            {...baseSession, clientId: 'another-client'},
            {...baseSession, issuer: 'https://another-issuer.example'}
        ]) {
            const cookies = createCookiesWithSession(foreignSession);
            await expect(oidc.getSession({cookies})).resolves.toBeNull();
            expect(cookies.delete).toHaveBeenCalledWith('oidc_session', expect.any(Object));
        }
    });
});
import '$app/server';
