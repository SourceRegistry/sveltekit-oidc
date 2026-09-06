import {isRedirect, type Cookies} from '@sveltejs/kit';
import {exportJWK, sign} from '@sourceregistry/node-jwt';
import {generateKeyPairSync} from 'node:crypto';
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

describe('OIDC refresh validation and concurrency', () => {
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
});

describe('OIDC callback state recovery', () => {
    const endpoints = {
        issuer: 'https://identity.example/realms/test',
        authorization_endpoint: 'https://identity.example/authorize',
        token_endpoint: 'https://identity.example/token'
    };

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
});
