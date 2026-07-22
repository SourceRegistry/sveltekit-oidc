import {type Action, type Cookies, error, type Handle, redirect, type RequestEvent} from '@sveltejs/kit';
import {randomBytes} from 'node:crypto';
import {decode, fromWeb, verify} from '@sourceregistry/node-jwt/promises';
import type {JWKSResolver, JWT as JSONWebToken} from '@sourceregistry/node-jwt';

import {createOIDCCookieStore} from './cookies.js';
import {asAuthorizationHeader, createClientSecretJwtAssertion, createPrivateKeyJwtAssertion, fetchJson} from './jwt.js';
import {isSessionExpired, normalizeTokens, shouldRefresh} from './session.js';
import type {
    MinimalRequestEvent,
    MinimalRequestHandler,
    OIDCActionOptions,
    OIDCBackChannelLogoutClaims,
    OIDCCallbackHandlerOptions,
    OIDCCallbackResult,
    OIDCClientAuthMethod,
    OIDCDiscoveryDocument,
    OIDCHandleLocals,
    OIDCInstance,
    OIDCLogger,
    OIDCLoginOptions,
    OIDCLogoutOptions,
    OIDCOptions,
    OIDCPersistedSession,
    OIDCPublicSession,
    OIDCSession,
    OIDCSessionManagementConfig,
    OIDCTokenResponse,
    OIDCUserClaims,
    SupportedAlgorithm
} from './types.js';
import {
    absoluteUrl,
    base64UrlEncode,
    buildCookieOptions,
    collectGroups,
    createPKCEPair,
    internalRedirectPath,
    normalizeIssuer,
    normalizeScope,
    parseProviderError,
    toPublicSession,
    validateIdTokenClaims,
    validateUserInfoSubject
} from './utils.js';
import {createInMemoryBackChannelLogoutStore, createInMemorySessionStore} from './store.js';

export type * from './types.js';
export {createInMemoryBackChannelLogoutStore, createInMemorySessionStore} from './store.js';

const OIDC_SESSION_REVALIDATION_DEPENDENCY = 'oidc:session';
const LOGIN_PROMPTS = new Set<NonNullable<OIDCLoginOptions['prompt']>>([
    'login',
    'consent',
    'none',
    'select_account'
]);

function silentReauthenticationResponse(status: 'authenticated' | 'logged_out') {
    return new Response(
        `<!doctype html><html lang="en" data-oidc-silent-reauth="${status}"><head><meta charset="utf-8"><title>OIDC session check</title></head><body></body></html>`,
        {
            headers: {
                'Content-Type': 'text/html; charset=utf-8',
                'Cache-Control': 'no-store',
                'Content-Security-Policy': "default-src 'none'; frame-ancestors 'self'"
            }
        }
    );
}

function buildLogger(logger: OIDCLogger | false | undefined): Required<OIDCLogger> {
    const noop = () => {};
    if (logger === false) return {debug: noop, info: noop, warn: noop, error: noop};
    if (logger)
        return {
            debug: (...a) => logger.debug?.(...a),
            info: (...a) => logger.info?.(...a),
            warn: (...a) => logger.warn?.(...a),
            error: (...a) => logger.error?.(...a)
        };
    const p = '[sveltekit-oidc]';
    return {
        debug: (...a) => console.debug(p, ...a),
        info: (...a) => console.info(p, ...a),
        warn: (...a) => console.warn(p, ...a),
        error: (...a) => console.error(p, ...a)
    };
}

export function createOIDC<TIdentity extends OIDCUserClaims = OIDCUserClaims, TRequestData = undefined>(
    options: OIDCOptions<TIdentity, TRequestData>
): OIDCInstance<TIdentity, TRequestData> {
    const log = buildLogger(options.logger);
    const sessionStore =
        options.sessionStore === 'memory' ? createInMemorySessionStore<TIdentity>() : options.sessionStore;
    const backChannelLogoutStore =
        options.backChannelLogoutStore === 'memory'
            ? createInMemoryBackChannelLogoutStore<TIdentity>()
            : options.backChannelLogoutStore;

    const cookieOptions = buildCookieOptions(options.cookieOptions);
    const clockSkewSeconds = options.clockSkewSeconds ?? 30;
    const refreshToleranceSeconds = options.refreshToleranceSeconds ?? 30;
    const sessionMaxAgeSeconds = options.sessionMaxAgeSeconds ?? 60 * 60 * 8;
    if (!Number.isFinite(sessionMaxAgeSeconds) || sessionMaxAgeSeconds <= 0) {
        throw new TypeError('sessionMaxAgeSeconds must be a positive finite number');
    }
    const sessionCookieName = options.sessionCookieName ?? 'oidc_session';
    const stateCookieName = options.stateCookieName ?? 'oidc_auth_state';
    const defaultScope = normalizeScope(options.scope);
    const loginPath = options.loginPath ?? '/auth/login';
    const logoutPath = options.logoutPath ?? '/auth/logout';
    const redirectPath = options.redirectPath ?? '/auth/callback';
    const clientAuthMethod: OIDCClientAuthMethod =
        options.clientAuthMethod ?? (options.clientSecret ? 'client_secret_basic' : 'none');
    const fetchImpl: typeof fetch = options.fetch ?? fetch;

    const cookieStore = createOIDCCookieStore<TIdentity>(
        options.cookieSecret,
        sessionCookieName,
        stateCookieName,
        cookieOptions
    );

    let metadataPromise: Promise<OIDCDiscoveryDocument> | undefined;
    let jwksPromise: Promise<JWKSResolver> | undefined;

    function hasCurrentSessionShape(session: OIDCSession<TIdentity> | null): session is OIDCSession<TIdentity> {
        return Boolean(session?.identity?.sub && session.idTokenClaims?.sub);
    }

    async function readPersistedSession(
        cookies: RequestEvent['cookies']
    ): Promise<OIDCPersistedSession<TIdentity> | null> {
        if (!sessionStore) {
            const session = cookieStore.readSession(cookies);
            if (!session) return null;
            if (!hasCurrentSessionShape(session)) {
                log.debug('Discarding an incompatible OIDC session');
                cookieStore.clearSession(cookies);
                return null;
            }
            return {session};
        }

        const reference = cookieStore.readSessionReference(cookies);
        if (!reference?.id) {
            log.debug('No OIDC session reference cookie is present');
            return null;
        }

        const session = await sessionStore.get(reference.id);
        if (!session) {
            log.debug('OIDC session reference has no matching persisted session');
            cookieStore.clearSessionReference(cookies);
            return null;
        }
        if (!hasCurrentSessionShape(session)) {
            log.debug('Discarding an incompatible persisted OIDC session');
            await sessionStore.delete(reference.id);
            cookieStore.clearSessionReference(cookies);
            return null;
        }

        return {
            id: reference.id,
            session
        };
    }

    async function writePersistedSession(
        cookies: RequestEvent['cookies'],
        session: OIDCSession<TIdentity>,
        sessionId?: string
    ): Promise<void> {
        if (!sessionStore) {
            cookieStore.writeSession(cookies, session);
            return;
        }

        const id = sessionId ?? base64UrlEncode(randomBytes(24));
        await sessionStore.set(id, session);
        cookieStore.writeSessionReference(cookies, {id});
    }

    async function clearPersistedSession(cookies: RequestEvent['cookies'], sessionId?: string): Promise<void> {
        if (!sessionStore) {
            cookieStore.clearSession(cookies);
            return;
        }

        const id = sessionId ?? cookieStore.readSessionReference(cookies)?.id;
        if (id) {
            await sessionStore.delete(id);
        }
        cookieStore.clearSessionReference(cookies);
    }

    async function getMetadata() {
        if (!metadataPromise) {
            metadataPromise = (async () => {
                if (options.endpoints?.authorization_endpoint && options.endpoints?.token_endpoint) {
                    return {
                        issuer: normalizeIssuer(options.issuer ?? options.endpoints.issuer ?? ''),
                        jwks_uri: options.endpoints.jwks_uri ?? '',
                        ...options.endpoints
                    } as OIDCDiscoveryDocument;
                }

                const issuer = options.issuer ? normalizeIssuer(options.issuer) : undefined;
                const discoveryUrl =
                    options.discoveryUrl ?? (issuer ? `${issuer}/.well-known/openid-configuration` : undefined);

                if (!discoveryUrl) {
                    throw error(500, {
                        message: 'OIDC issuer or discoveryUrl must be configured'
                    });
                }

                const document = await fetchJson<OIDCDiscoveryDocument>(discoveryUrl, undefined, fetchImpl);
                return {
                    ...document,
                    ...options.endpoints,
                    issuer: normalizeIssuer(document.issuer)
                };
            })();
        }

        return metadataPromise;
    }

    async function getJwks() {
        if (!jwksPromise) {
            jwksPromise = getMetadata().then((metadata) => {
                if (!metadata.jwks_uri) {
                    throw error(500, {
                        message: 'OIDC jwks_uri is required to validate id_token values'
                    });
                }

                return fromWeb(metadata.jwks_uri, {
                    overrideEndpointCheck: true,
                    fetch: fetchImpl
                });
            });
        }

        return jwksPromise;
    }

    async function verifyJwtWithJwks<T extends Record<string, unknown>>(
        token: string,
        verifyOptions: {
            issuer: string;
            audience: string;
            algorithms?: SupportedAlgorithm[];
            clockSkew?: number;
        }
    ): Promise<T> {
        let decoded: JSONWebToken;
        try {
            decoded = await decode(token);
        } catch {
            throw error(400, {message: 'Invalid JWT format'});
        }

        const jwks = await getJwks();
        const key = decoded.header.kid ? await jwks.key(decoded.header.kid) : (await jwks.list())[0];
        if (!key) {
            throw error(401, {
                message: 'Unable to resolve a signing key from JWKS'
            });
        }

        try {
            const result = await verify(token, key.toKeyObject(), verifyOptions);
            return result.payload as T;
        } catch (err) {
            throw error(401, {
                message:
                    typeof err === 'object' && err && 'reason' in err ? String(err.reason) : 'JWT verification failed'
            });
        }
    }

    async function buildTokenRequestAuth(tokenEndpoint: string) {
        const headers: Record<string, string> = {
            'content-type': 'application/x-www-form-urlencoded'
        };
        const body = new URLSearchParams();

        switch (clientAuthMethod) {
            case 'none':
                body.set('client_id', options.clientId);
                return {headers, body};
            case 'client_secret_basic':
                if (!options.clientSecret) {
                    throw error(500, {
                        message: 'clientSecret is required for client_secret_basic'
                    });
                }
                headers.authorization = asAuthorizationHeader(options.clientId, options.clientSecret);
                return {headers, body};
            case 'client_secret_post':
                if (!options.clientSecret) {
                    throw error(500, {
                        message: 'clientSecret is required for client_secret_post'
                    });
                }
                body.set('client_id', options.clientId);
                body.set('client_secret', options.clientSecret);
                return {headers, body};
            case 'client_secret_jwt':
                body.set('client_id', options.clientId);
                body.set(
                    'client_assertion',
                    await createClientSecretJwtAssertion({
                        tokenEndpoint,
                        clientId: options.clientId,
                        clientSecret: options.clientSecret,
                        ...options.clientSecretJwt
                    })
                );
                body.set('client_assertion_type', 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer');
                return {headers, body};
            case 'private_key_jwt':
                if (!options.privateKeyJwt?.privateKey) {
                    throw error(500, {
                        message: 'privateKeyJwt.privateKey is required for private_key_jwt'
                    });
                }
                body.set('client_id', options.clientId);
                body.set(
                    'client_assertion',
                    await createPrivateKeyJwtAssertion({
                        tokenEndpoint,
                        clientId: options.clientId,
                        ...options.privateKeyJwt
                    })
                );
                body.set('client_assertion_type', 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer');
                return {headers, body};
            default:
                throw error(500, {
                    message: `Unsupported client authentication method '${clientAuthMethod}'`
                });
        }
    }

    async function exchangeCode(params: {code: string; redirectUri: string; codeVerifier: string}) {
        const metadata = await getMetadata();
        const auth = await buildTokenRequestAuth(metadata.token_endpoint);
        auth.body.set('grant_type', 'authorization_code');
        auth.body.set('code', params.code);
        auth.body.set('redirect_uri', params.redirectUri);
        auth.body.set('code_verifier', params.codeVerifier);

        return fetchJson<OIDCTokenResponse>(
            metadata.token_endpoint,
            {
                method: 'POST',
                headers: auth.headers,
                body: auth.body
            },
            fetchImpl
        );
    }

    async function refreshTokens(refreshToken: string) {
        const metadata = await getMetadata();
        const auth = await buildTokenRequestAuth(metadata.token_endpoint);
        auth.body.set('grant_type', 'refresh_token');
        auth.body.set('refresh_token', refreshToken);

        return fetchJson<OIDCTokenResponse>(
            metadata.token_endpoint,
            {
                method: 'POST',
                headers: auth.headers,
                body: auth.body
            },
            fetchImpl
        );
    }

    async function validateIdToken(idToken: string, nonce: string) {
        const metadata = await getMetadata();
        const claims = await verifyJwtWithJwks<OIDCUserClaims>(idToken, {
            issuer: metadata.issuer,
            audience: options.clientId,
            algorithms: metadata.id_token_signing_alg_values_supported as SupportedAlgorithm[] | undefined,
            clockSkew: clockSkewSeconds
        });
        validateIdTokenClaims(claims, nonce);
        return claims;
    }

    async function resolveIdentity(
        idTokenClaims: OIDCUserClaims,
        userInfo: OIDCUserClaims | undefined,
        reason: 'login' | 'refresh'
    ): Promise<TIdentity> {
        if (options.resolveIdentity) {
            return options.resolveIdentity({idTokenClaims, userInfo, reason});
        }

        return {
            ...idTokenClaims,
            ...userInfo,
            groups: userInfo?.groups ?? idTokenClaims.groups
        } as TIdentity;
    }

    async function validateBackChannelLogoutToken(logoutToken: string) {
        const metadata = await getMetadata();
        const claims = await verifyJwtWithJwks<OIDCBackChannelLogoutClaims>(logoutToken, {
            issuer: metadata.issuer,
            audience: options.clientId,
            clockSkew: clockSkewSeconds
        });
        if (!claims.events?.['http://schemas.openid.net/event/backchannel-logout']) {
            throw error(400, {message: 'Invalid logout_token events claim'});
        }
        if (!claims.sid && !claims.sub) {
            throw error(400, {message: 'logout_token must contain sid or sub'});
        }
        if ('nonce' in claims && claims.nonce !== undefined) {
            throw error(400, {message: 'logout_token must not contain nonce'});
        }

        return claims;
    }

    async function fetchUserInfo(accessToken: string) {
        const metadata = await getMetadata();
        if (!metadata.userinfo_endpoint) {
            return undefined;
        }

        return fetchJson<OIDCUserClaims>(
            metadata.userinfo_endpoint,
            {
                headers: {
                    authorization: `Bearer ${accessToken}`
                }
            },
            fetchImpl
        );
    }

    async function isRevoked(session: OIDCSession<TIdentity> | null) {
        if (!session || !backChannelLogoutStore) {
            return false;
        }

        return backChannelLogoutStore.isRevoked(session);
    }

    async function maybeRefreshSession(
        cookies: RequestEvent['cookies'],
        persisted: OIDCPersistedSession<TIdentity> | null,
        event?: MinimalRequestEvent
    ) {
        const session = persisted?.session ?? null;
        if (!session) {
            return null;
        }
        if (isSessionExpired(session, sessionMaxAgeSeconds)) {
            const now = Math.floor(Date.now() / 1000);
            log.debug('OIDC session expired — clearing session', {
                reason:
                    session.createdAt + sessionMaxAgeSeconds <= now
                        ? 'session_max_age'
                        : 'access_token_expired_without_refresh_token',
                createdAt: session.createdAt,
                expiresAt: session.tokens.expiresAt,
                refreshExpiresAt: session.tokens.refreshExpiresAt,
                hasRefreshToken: Boolean(session.tokens.refreshToken)
            });
            await clearPersistedSession(cookies, persisted?.id);
            return null;
        }
        if (await isRevoked(session)) {
            log.debug('OIDC session was revoked by back-channel logout — clearing session', {
                hasSid: Boolean(session.sid),
                hasSubject: Boolean(session.sub)
            });
            await clearPersistedSession(cookies, persisted?.id);
            return null;
        }
        if (!shouldRefresh(session, refreshToleranceSeconds)) {
            return session;
        }

        try {
            log.debug('Refreshing OIDC session tokens', {
                expiresAt: session.tokens.expiresAt,
                refreshExpiresAt: session.tokens.refreshExpiresAt
            });
            const tokenResponse = await refreshTokens(session.tokens.refreshToken as string);
            const idTokenClaims = tokenResponse.id_token
                ? await validateIdToken(tokenResponse.id_token, session.nonce as string)
                : session.idTokenClaims;
            const userInfo =
                options.fetchUserInfo !== false ? await fetchUserInfo(tokenResponse.access_token) : session.userInfo;
            validateUserInfoSubject(idTokenClaims, userInfo);
            const identity = await resolveIdentity(idTokenClaims, userInfo, 'refresh');
            const nextSession: OIDCSession<TIdentity> = {
                ...session,
                sub: idTokenClaims.sub,
                sid: idTokenClaims.sid ?? session.sid,
                groups: collectGroups(idTokenClaims, userInfo, identity),
                idTokenClaims,
                userInfo,
                identity,
                sessionState: tokenResponse.session_state ?? session.sessionState,
                tokens: normalizeTokens(tokenResponse, defaultScope, session.tokens),
                refreshedAt: Math.floor(Date.now() / 1000)
            };
            await options.beforeSessionPersist?.({
                session: nextSession,
                reason: 'refresh',
                event,
                tokenResponse
            });
            await writePersistedSession(cookies, nextSession, persisted?.id);
            log.debug('OIDC session tokens refreshed', {
                expiresAt: nextSession.tokens.expiresAt,
                refreshExpiresAt: nextSession.tokens.refreshExpiresAt,
                hasRefreshToken: Boolean(nextSession.tokens.refreshToken)
            });
            return nextSession;
        } catch (err) {
            log.error('Token refresh failed — clearing session', err);
            await clearPersistedSession(cookies, persisted?.id);
            return null;
        }
    }

    async function getSession(event: {cookies: Cookies}) {
        return maybeRefreshSession(
            event.cookies,
            await readPersistedSession(event.cookies),
            'url' in event && 'request' in event ? (event as MinimalRequestEvent) : undefined
        );
    }

    async function signIn(event: {cookies: Cookies; url: URL}, loginOptions: OIDCLoginOptions = {}): Promise<never> {
        const metadata = await getMetadata();
        const pkce = createPKCEPair();
        const state = base64UrlEncode(randomBytes(24));
        const nonce = base64UrlEncode(randomBytes(24));
        const returnTo = internalRedirectPath(event, loginOptions.returnTo ?? options.defaultLoginRedirect, '/');
        const existingSession = loginOptions.prompt === 'none' ? await readPersistedSession(event.cookies) : null;

        cookieStore.writeState(event.cookies, {
            state,
            nonce,
            codeVerifier: pkce.verifier,
            returnTo,
            prompt: loginOptions.prompt,
            originalSub: existingSession?.session.sub,
            createdAt: Math.floor(Date.now() / 1000)
        });

        const redirectUri = absoluteUrl(event, redirectPath);
        const authorizationUrl = new URL(metadata.authorization_endpoint);
        authorizationUrl.searchParams.set('client_id', options.clientId);
        authorizationUrl.searchParams.set('response_type', 'code');
        authorizationUrl.searchParams.set('redirect_uri', redirectUri);
        authorizationUrl.searchParams.set('scope', normalizeScope(loginOptions.scope ?? defaultScope).join(' '));
        authorizationUrl.searchParams.set('state', state);
        authorizationUrl.searchParams.set('nonce', nonce);
        authorizationUrl.searchParams.set('code_challenge', pkce.challenge);
        authorizationUrl.searchParams.set('code_challenge_method', 'S256');

        if (options.audience) {
            authorizationUrl.searchParams.set('audience', options.audience);
        }
        if (loginOptions.prompt) {
            authorizationUrl.searchParams.set('prompt', loginOptions.prompt);
        }
        if (loginOptions.prompt === 'none' && existingSession?.session.tokens.idToken) {
            authorizationUrl.searchParams.set('id_token_hint', existingSession.session.tokens.idToken);
        }
        for (const [key, value] of Object.entries(loginOptions.extraParams ?? {})) {
            authorizationUrl.searchParams.set(key, value);
        }

        throw redirect(302, authorizationUrl.toString());
    }

    async function handleCallback(event: {url: URL; cookies: Cookies}): Promise<OIDCCallbackResult<TIdentity>> {
        const providerError = parseProviderError(event);
        if (providerError) {
            throw providerError;
        }

        const stateCookie = cookieStore.readState(event.cookies);
        const state = event.url.searchParams.get('state');
        const code = event.url.searchParams.get('code');

        if (!stateCookie || !state || !code || stateCookie.state !== state) {
            cookieStore.clearState(event.cookies);
            log.warn('Invalid or expired callback state — restarting login flow');
            return signIn(event);
        }

        cookieStore.clearState(event.cookies);

        const tokenResponse = await exchangeCode({
            code,
            redirectUri: absoluteUrl(event, redirectPath),
            codeVerifier: stateCookie.codeVerifier
        });

        if (!tokenResponse.id_token) {
            throw error(401, {
                message: 'OIDC callback response must include an id_token'
            });
        }

        const idTokenClaims = await validateIdToken(tokenResponse.id_token, stateCookie.nonce);
        if (stateCookie.prompt === 'none' && stateCookie.originalSub && idTokenClaims.sub !== stateCookie.originalSub) {
            throw error(401, {message: 'Silent re-authentication returned a different End-User'});
        }
        const userInfo =
            options.fetchUserInfo === false
                ? undefined
                : await fetchUserInfo(tokenResponse.access_token).catch(() => undefined);
        validateUserInfoSubject(idTokenClaims, userInfo);
        const identity = await resolveIdentity(idTokenClaims, userInfo, 'login');
        const metadata = await getMetadata();
        const now = Math.floor(Date.now() / 1000);
        const session: OIDCSession<TIdentity> = {
            issuer: metadata.issuer,
            clientId: options.clientId,
            nonce: stateCookie.nonce,
            sub: idTokenClaims.sub,
            sid: idTokenClaims.sid,
            sessionState: tokenResponse.session_state ?? event.url.searchParams.get('session_state') ?? undefined,
            groups: collectGroups(idTokenClaims, userInfo, identity),
            idTokenClaims,
            userInfo,
            identity,
            tokens: normalizeTokens(tokenResponse, defaultScope),
            createdAt: now,
            refreshedAt: now
        };
        await options.beforeSessionPersist?.({
            session,
            reason: 'login',
            event: event as MinimalRequestEvent,
            tokenResponse
        });
        const existingSession = stateCookie.prompt === 'none' ? await readPersistedSession(event.cookies) : null;
        await writePersistedSession(event.cookies, session, existingSession?.id);

        return {
            session,
            returnTo: stateCookie.returnTo
        };
    }

    async function signOut(
        event: {
            cookies: Cookies;
            url: URL;
        },
        logoutOptions: OIDCLogoutOptions = {}
    ): Promise<never> {
        const metadata = await getMetadata();
        const persisted = await readPersistedSession(event.cookies);
        const session = persisted?.session ?? null;
        cookieStore.clearState(event.cookies);
        await clearPersistedSession(event.cookies, persisted?.id);
        const postLogoutRedirectPath = internalRedirectPath(
            event,
            logoutOptions.postLogoutRedirectUri ?? options.defaultLogoutRedirect ?? options.postLogoutRedirectUri,
            '/'
        );

        if (logoutOptions.clearSessionOnly || !metadata.end_session_endpoint) {
            throw redirect(302, postLogoutRedirectPath);
        }

        const url = new URL(metadata.end_session_endpoint);
        if (session?.tokens.idToken) {
            url.searchParams.set('id_token_hint', session.tokens.idToken);
        }
        // The provider needs client context to validate the post-logout URI
        // even when the local session (and therefore id_token_hint) is gone.
        url.searchParams.set('client_id', options.clientId);
        url.searchParams.set('post_logout_redirect_uri', absoluteUrl(event, postLogoutRedirectPath));
        if (logoutOptions.state) {
            url.searchParams.set('state', logoutOptions.state);
        }

        throw redirect(302, url.toString());
    }

    async function handleBackChannelLogout(event: {request: Request}) {
        const metadata = await getMetadata();
        if (!metadata.backchannel_logout_supported) {
            throw error(400, {
                message: 'Provider does not advertise back-channel logout support'
            });
        }
        if (!backChannelLogoutStore) {
            throw error(500, {
                message: 'backChannelLogoutStore is required for back-channel logout with cookie sessions'
            });
        }

        const form = await event.request.formData();
        const logoutToken = form.get('logout_token')?.toString();
        if (!logoutToken) {
            throw error(400, {message: 'logout_token is required'});
        }

        const claims = await validateBackChannelLogoutToken(logoutToken);
        await backChannelLogoutStore.revoke({
            issuer: claims.iss,
            clientId: options.clientId,
            sid: claims.sid,
            sub: claims.sub,
            jti: claims.jti,
            iat: claims.iat
        });

        return new Response(null, {status: 200});
    }

    async function requireAuth(event: {url: URL; cookies: RequestEvent['cookies']}, returnTo?: string) {
        const session = await getSession(event);
        if (session) {
            return session;
        }

        throw redirect(
            302,
            `${absoluteUrl(event, loginPath)}?returnTo=${encodeURIComponent(
                internalRedirectPath(event, returnTo ?? `${event.url.pathname}${event.url.search}`, '/')
            )}`
        );
    }

    const handle: Handle = async ({event, resolve}) => {
        const oidc = await createRequestContext(event);
        (
            event.locals as typeof event.locals & {
                oidc: OIDCHandleLocals<TIdentity, TRequestData>;
            }
        ).oidc = oidc;
        return resolve(event);
    };

    async function createRequestContext(
        event: MinimalRequestEvent
    ): Promise<OIDCHandleLocals<TIdentity, TRequestData>> {
        const session = await getSession(event);
        const data = session && options.loadRequestData ? await options.loadRequestData({session, event}) : null;
        const context = {
            isAuthenticated: Boolean(session),
            session,
            identity: session?.identity,
            data,
            requireAuth: async () => {
                if (!session) {
                    throw error(401, {message: 'Authentication required'});
                }
                return session;
            },
            clearSession: async () => clearPersistedSession(event.cookies)
        } satisfies OIDCHandleLocals<TIdentity, TRequestData>;
        return context;
    }

    function loginHandler<T extends MinimalRequestEvent = RequestEvent>(
        defaults: OIDCLoginOptions = {}
    ): MinimalRequestHandler<T> {
        return async (event) => {
            const returnTo = event.url.searchParams.get('returnTo') ?? defaults.returnTo;
            const requestedPrompt = event.url.searchParams.get('prompt');
            const prompt = requestedPrompt && LOGIN_PROMPTS.has(requestedPrompt as NonNullable<OIDCLoginOptions['prompt']>)
                ? requestedPrompt as NonNullable<OIDCLoginOptions['prompt']>
                : defaults.prompt;
            return signIn(event, {...defaults, returnTo, prompt});
        };
    }

    function callbackHandler<T extends MinimalRequestEvent = RequestEvent>(
        handlerOptions: OIDCCallbackHandlerOptions<TIdentity> = {}
    ): MinimalRequestHandler<T> {
        return async (event) => {
            const stateCookie = cookieStore.readState(event.cookies);
            const callbackState = event.url.searchParams.get('state');
            const isSilentReauthentication = Boolean(
                stateCookie?.prompt === 'none' && callbackState && callbackState === stateCookie.state
            );
            try {
                const result = await handleCallback(event);
                if (isSilentReauthentication) {
                    return silentReauthenticationResponse('authenticated');
                }
                const response = await handlerOptions.onsuccess?.(event, result);
                if (response) return response;
                throw redirect(302, internalRedirectPath(event, handlerOptions.redirectTo ?? result.returnTo, '/'));
            } catch (err) {
                if (isSilentReauthentication) {
                    cookieStore.clearState(event.cookies);
                    const persisted = await readPersistedSession(event.cookies);
                    await clearPersistedSession(event.cookies, persisted?.id);
                    log.debug('Silent OIDC re-authentication failed — clearing local session');
                    return silentReauthenticationResponse('logged_out');
                }
                const response = await handlerOptions.onfailure?.(event, err);
                if (response) {
                    return response;
                }

                throw err;
            }
        };
    }

    function logoutHandler<T extends MinimalRequestEvent = RequestEvent>(
        defaults: OIDCLogoutOptions = {}
    ): MinimalRequestHandler<T> {
        return async (event) => {
            const form = await event.request.formData().catch(() => null);
            const postLogoutRedirectUri =
                event.url.searchParams.get('postLogoutRedirectUri') ??
                form?.get('postLogoutRedirectUri')?.toString() ??
                defaults.postLogoutRedirectUri;
            const clearSessionOnly =
                event.url.searchParams.get('clearSessionOnly') === '1' ||
                event.url.searchParams.get('clearSessionOnly') === 'true' ||
                form?.get('clearSessionOnly')?.toString() === '1' ||
                form?.get('clearSessionOnly')?.toString() === 'true' ||
                defaults.clearSessionOnly;

            return signOut(event, {
                ...defaults,
                postLogoutRedirectUri,
                clearSessionOnly
            });
        };
    }

    function backChannelLogoutHandler<T extends MinimalRequestEvent = RequestEvent>(): MinimalRequestHandler<T> {
        return async (event) => handleBackChannelLogout(event);
    }

    function createActions(actionOptions: OIDCActionOptions = {}) {
        return {
            login: (async (event: RequestEvent) => {
                const form = await event.request.formData();
                const returnTo =
                    (form.get('returnTo')?.toString() || actionOptions.defaultReturnTo || undefined) ?? undefined;

                return signIn(event, {returnTo});
            }) satisfies Action,
            logout: (async (event: RequestEvent) => {
                const form = await event.request.formData();
                const postLogoutRedirectUri =
                    (form.get('postLogoutRedirectUri')?.toString() ||
                        actionOptions.defaultPostLogoutRedirectUri ||
                        undefined) ??
                    undefined;
                const clearSessionOnly =
                    form.get('clearSessionOnly')?.toString() === '1' ||
                    form.get('clearSessionOnly')?.toString() === 'true';

                return signOut(event, {postLogoutRedirectUri, clearSessionOnly});
            }) satisfies Action
        } as const;
    }

    async function getSessionManagementConfig(): Promise<OIDCSessionManagementConfig> {
        const metadata = await getMetadata();
        return {
            clientId: options.clientId,
            issuer: metadata.issuer,
            loginPath,
            logoutPath,
            redirectPath,
            metadata: {
                issuer: metadata.issuer,
                check_session_iframe: metadata.check_session_iframe,
                end_session_endpoint: metadata.end_session_endpoint,
                backchannel_logout_supported: metadata.backchannel_logout_supported,
                backchannel_logout_session_supported: metadata.backchannel_logout_session_supported
            },
            checkSessionIframe: metadata.check_session_iframe,
            supportsSessionIframe: Boolean(metadata.check_session_iframe),
            backChannelLogoutSupported: Boolean(metadata.backchannel_logout_supported),
            backChannelLogoutSessionSupported: Boolean(metadata.backchannel_logout_session_supported)
        };
    }

    function projectPublicSession(
        context: OIDCHandleLocals<TIdentity, TRequestData> | null | undefined,
        depends?: (dependency: string) => void
    ): OIDCPublicSession<TIdentity> | null {
        depends?.(OIDC_SESSION_REVALIDATION_DEPENDENCY);
        if (!context?.session) return null;

        const base = toPublicSession(context.session);
        if (!base) return null;
        const publicSession = options.createPublicSession
            ? options.createPublicSession({
                  session: context.session,
                  data: context.data,
                  base
              })
            : base;

        return depends
            ? {
                  ...publicSession,
                  revalidationDependency: OIDC_SESSION_REVALIDATION_DEPENDENCY
              }
            : publicSession;
    }

    return {
        handle,
        createRequestContext,
        getMetadata,
        getSession,
        getPublicSession: async (
            event: MinimalRequestEvent & {
                depends?: (dependency: string) => void;
            }
        ): Promise<OIDCPublicSession<TIdentity> | null> =>
            projectPublicSession(await createRequestContext(event), event.depends),
        toPublicSession: projectPublicSession,
        getSessionManagementConfig,
        login: signIn,
        logout: signOut,
        handleCallback,
        handleBackChannelLogout,
        loginHandler,
        callbackHandler,
        logoutHandler,
        backChannelLogoutHandler,
        createActions,
        requireAuth,
        clearSession: async (cookies) => clearPersistedSession(cookies)
    };
}

export const OpenIDConnect = createOIDC;
