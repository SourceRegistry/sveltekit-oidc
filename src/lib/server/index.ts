import {
    type Action,
    type Cookies,
    error,
    type Handle,
    redirect,
    type RequestEvent,
} from '@sveltejs/kit';
import {randomBytes} from 'node:crypto';
import {decode, fromWeb, verify} from '@sourceregistry/node-jwt/promises';
import type {JWKSResolver, JWT as JSONWebToken} from '@sourceregistry/node-jwt';

import {createOIDCCookieStore} from './cookies.js';
import {asAuthorizationHeader, createClientSecretJwtAssertion, createPrivateKeyJwtAssertion, fetchJson} from './jwt.js';
import {isSessionExpired, normalizeTokens, shouldRefresh} from './session.js';
import type {
    MinimalRequestEvent, MinimalRequestHandler,
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

function buildLogger(logger: OIDCLogger | false | undefined): Required<OIDCLogger> {
    const noop = () => {
    };
    if (logger === false) return {debug: noop, info: noop, warn: noop, error: noop};
    if (logger) return {
        debug: (...a) => logger.debug?.(...a),
        info: (...a) => logger.info?.(...a),
        warn: (...a) => logger.warn?.(...a),
        error: (...a) => logger.error?.(...a),
    };
    const p = '[sveltekit-oidc]';
    return {
        debug: (...a) => console.debug(p, ...a),
        info: (...a) => console.info(p, ...a),
        warn: (...a) => console.warn(p, ...a),
        error: (...a) => console.error(p, ...a),
    };
}

export function createOIDC<
    TClaims extends OIDCUserClaims = OIDCUserClaims,
    TSession extends OIDCSession<TClaims> = OIDCSession<TClaims>
>(options: OIDCOptions<TClaims, TSession>): OIDCInstance<TClaims, TSession> {
    const log = buildLogger(options.logger);
    const sessionStore = options.sessionStore === 'memory'
        ? createInMemorySessionStore<TClaims, TSession>()
        : options.sessionStore;
    const backChannelLogoutStore = options.backChannelLogoutStore === 'memory'
        ? createInMemoryBackChannelLogoutStore<TClaims, TSession>()
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

    const cookieStore = createOIDCCookieStore<TClaims, TSession>(
        options.cookieSecret,
        sessionCookieName,
        stateCookieName,
        cookieOptions
    );

    let metadataPromise: Promise<OIDCDiscoveryDocument> | undefined;
    let jwksPromise: Promise<JWKSResolver> | undefined;

    async function readPersistedSession(
        cookies: RequestEvent['cookies']
    ): Promise<OIDCPersistedSession<TClaims, TSession> | null> {
        if (!sessionStore) {
            const session = cookieStore.readSession(cookies);
            return session ? {session} : null;
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

        return {
            id: reference.id,
            session
        };
    }

    async function writePersistedSession(
        cookies: RequestEvent['cookies'],
        session: TSession,
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

    async function clearPersistedSession(
        cookies: RequestEvent['cookies'],
        sessionId?: string
    ): Promise<void> {
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
                    throw error(500, {message: 'OIDC issuer or discoveryUrl must be configured'});
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
                    throw error(500, {message: 'OIDC jwks_uri is required to validate id_token values'});
                }

                return fromWeb(metadata.jwks_uri, {overrideEndpointCheck: true, fetch: fetchImpl});
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
            throw error(401, {message: 'Unable to resolve a signing key from JWKS'});
        }

        try {
            const result = await verify(token, key.toKeyObject(), verifyOptions);
            return result.payload as T;
        } catch (err) {
            throw error(401, {
                message:
                    typeof err === 'object' && err && 'reason' in err
                        ? String(err.reason)
                        : 'JWT verification failed'
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
                    throw error(500, {message: 'clientSecret is required for client_secret_basic'});
                }
                headers.authorization = asAuthorizationHeader(options.clientId, options.clientSecret);
                return {headers, body};
            case 'client_secret_post':
                if (!options.clientSecret) {
                    throw error(500, {message: 'clientSecret is required for client_secret_post'});
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
                    throw error(500, {message: 'privateKeyJwt.privateKey is required for private_key_jwt'});
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
                throw error(500, {message: `Unsupported client authentication method '${clientAuthMethod}'`});
        }
    }

    async function exchangeCode(params: {
        code: string;
        redirectUri: string;
        codeVerifier: string;
    }) {
        const metadata = await getMetadata();
        const auth = await buildTokenRequestAuth(metadata.token_endpoint);
        auth.body.set('grant_type', 'authorization_code');
        auth.body.set('code', params.code);
        auth.body.set('redirect_uri', params.redirectUri);
        auth.body.set('code_verifier', params.codeVerifier);

        return fetchJson<OIDCTokenResponse>(metadata.token_endpoint, {
            method: 'POST',
            headers: auth.headers,
            body: auth.body
        }, fetchImpl);
    }

    async function refreshTokens(refreshToken: string) {
        const metadata = await getMetadata();
        const auth = await buildTokenRequestAuth(metadata.token_endpoint);
        auth.body.set('grant_type', 'refresh_token');
        auth.body.set('refresh_token', refreshToken);

        return fetchJson<OIDCTokenResponse>(metadata.token_endpoint, {
            method: 'POST',
            headers: auth.headers,
            body: auth.body
        }, fetchImpl);
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
        return options.transformClaims
            ? await options.transformClaims(claims)
            : (claims as TClaims);
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

        return fetchJson<OIDCUserClaims>(metadata.userinfo_endpoint, {
            headers: {
                authorization: `Bearer ${accessToken}`
            }
        }, fetchImpl);
    }

    async function isRevoked(session: TSession | null) {
        if (!session || !backChannelLogoutStore) {
            return false;
        }

        return backChannelLogoutStore.isRevoked(session);
    }

    async function maybeRefreshSession(
        cookies: RequestEvent['cookies'],
        persisted: OIDCPersistedSession<TClaims, TSession> | null
    ) {
        const session = persisted?.session ?? null;
        if (!session) {
            return null;
        }
        if (isSessionExpired(session, sessionMaxAgeSeconds)) {
            const now = Math.floor(Date.now() / 1000);
            log.debug('OIDC session expired — clearing session', {
                reason: session.createdAt + sessionMaxAgeSeconds <= now
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
            const claims = tokenResponse.id_token
                ? await validateIdToken(tokenResponse.id_token, session.nonce as string)
                : session.claims;
            const rawUser =
                options.fetchUserInfo !== false ? await fetchUserInfo(tokenResponse.access_token) : session.user;
            if (claims) {
                validateUserInfoSubject(claims, rawUser);
            }
            const user = options.transformUser
                ? await options.transformUser(rawUser, {claims})
                : (rawUser as TClaims | undefined);
            const nextSession: OIDCSession<TClaims> = {
                ...session,
                sub: claims?.sub ?? session.sub,
                sid: claims?.sid ?? session.sid,
                groups: collectGroups(claims, user, session.user, session.claims),
                claims,
                user,
                sessionState: tokenResponse.session_state ?? session.sessionState,
                tokens: normalizeTokens(tokenResponse, defaultScope, session.tokens),
                refreshedAt: Math.floor(Date.now() / 1000)
            };
            const finalSession = options.transformSession
                ? await options.transformSession(nextSession, {
                    tokenResponse,
                    claims,
                    user,
                    isRefresh: true
                })
                : (nextSession as TSession);
            await writePersistedSession(cookies, finalSession, persisted?.id);
            log.debug('OIDC session tokens refreshed', {
                expiresAt: finalSession.tokens.expiresAt,
                refreshExpiresAt: finalSession.tokens.refreshExpiresAt,
                hasRefreshToken: Boolean(finalSession.tokens.refreshToken)
            });
            return finalSession;
        } catch (err) {
            log.error('Token refresh failed — clearing session', err);
            await clearPersistedSession(cookies, persisted?.id);
            return null;
        }
    }

    async function getSession(event: { cookies: Cookies }) {
        const session = await maybeRefreshSession(event.cookies, await readPersistedSession(event.cookies));
        if (!session || !options.enrichSession) {
            return session;
        }
        return options.enrichSession(session, {event: event as MinimalRequestEvent});
    }

    async function signIn(event: { cookies: Cookies, url: URL }, loginOptions: OIDCLoginOptions = {}): Promise<never> {
        const metadata = await getMetadata();
        const pkce = createPKCEPair();
        const state = base64UrlEncode(randomBytes(24));
        const nonce = base64UrlEncode(randomBytes(24));
        const returnTo = internalRedirectPath(event, loginOptions.returnTo ?? options.defaultLoginRedirect, '/');

        cookieStore.writeState(event.cookies, {
            state,
            nonce,
            codeVerifier: pkce.verifier,
            returnTo,
            createdAt: Math.floor(Date.now() / 1000)
        });

        const redirectUri = absoluteUrl(event, redirectPath);
        const authorizationUrl = new URL(metadata.authorization_endpoint);
        authorizationUrl.searchParams.set('client_id', options.clientId);
        authorizationUrl.searchParams.set('response_type', 'code');
        authorizationUrl.searchParams.set('redirect_uri', redirectUri);
        authorizationUrl.searchParams.set(
            'scope',
            normalizeScope(loginOptions.scope ?? defaultScope).join(' ')
        );
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
        for (const [key, value] of Object.entries(loginOptions.extraParams ?? {})) {
            authorizationUrl.searchParams.set(key, value);
        }

        throw redirect(302, authorizationUrl.toString());
    }

    async function handleCallback(event: {
        url: URL,
        cookies: Cookies
    }): Promise<OIDCCallbackResult<TClaims, TSession>> {
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
            throw error(401, {message: 'OIDC callback response must include an id_token'});
        }

        const claims = await validateIdToken(tokenResponse.id_token, stateCookie.nonce);
        const rawUser =
            options.fetchUserInfo === false
                ? undefined
                : await fetchUserInfo(tokenResponse.access_token).catch(() => undefined);
        validateUserInfoSubject(claims, rawUser);
        const user = options.transformUser
            ? await options.transformUser(rawUser, {claims})
            : (rawUser as TClaims | undefined);
        const metadata = await getMetadata();
        const now = Math.floor(Date.now() / 1000);
        const session: OIDCSession<TClaims> = {
            issuer: metadata.issuer,
            clientId: options.clientId,
            nonce: stateCookie.nonce,
            sub: claims?.sub,
            sid: claims?.sid,
            sessionState: tokenResponse.session_state ?? event.url.searchParams.get('session_state') ?? undefined,
            groups: collectGroups(claims, user),
            user,
            claims,
            tokens: normalizeTokens(tokenResponse, defaultScope),
            createdAt: now,
            refreshedAt: now
        };
        const finalSession = options.transformSession
            ? await options.transformSession(session, {
                event: event as RequestEvent,
                tokenResponse,
                claims,
                user,
                isRefresh: false
            })
            : (session as TSession);

        await writePersistedSession(event.cookies, finalSession);

        return {
            session: finalSession,
            returnTo: stateCookie.returnTo
        };
    }

    async function signOut(event: {
        cookies: Cookies,
        url: URL
    }, logoutOptions: OIDCLogoutOptions = {}): Promise<never> {
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
        url.searchParams.set(
            'post_logout_redirect_uri',
            absoluteUrl(event, postLogoutRedirectPath)
        );
        if (logoutOptions.state) {
            url.searchParams.set('state', logoutOptions.state);
        }

        throw redirect(302, url.toString());
    }

    async function handleBackChannelLogout(event: { request: Request }) {
        const metadata = await getMetadata();
        if (!metadata.backchannel_logout_supported) {
            throw error(400, {message: 'Provider does not advertise back-channel logout support'});
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

    async function requireAuth(event: { url: URL, cookies: RequestEvent['cookies'] }, returnTo?: string) {
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
        const {oidc} = await hook(event);
        (event.locals as typeof event.locals & { oidc: OIDCHandleLocals<TClaims, TSession> }).oidc = oidc;
        return resolve(event);
    };

    async function hook(event: { cookies: Cookies, locals: App.Locals }) {
        const session = await getSession(event);
        const locals = {
            oidc: {
                isAuthenticated: Boolean(session),
                session,
                user: session?.user,
                claims: session?.claims,
                requireAuth: async () => {
                    if (!session) {
                        throw error(401, {message: 'Authentication required'});
                    }
                    return session;
                },
                clearSession: async () => clearPersistedSession(event.cookies)
            } satisfies OIDCHandleLocals<TClaims, TSession>
        };
        (event.locals as typeof event.locals & { oidc: OIDCHandleLocals<TClaims, TSession> }).oidc = locals.oidc;
        return locals;
    }

    function loginHandler<T extends MinimalRequestEvent = RequestEvent>(defaults: OIDCLoginOptions = {}): MinimalRequestHandler<T> {
        return async (event) => {
            const returnTo = event.url.searchParams.get('returnTo') ?? defaults.returnTo;
            return signIn(event, {...defaults, returnTo});
        };
    }

    function callbackHandler<T extends MinimalRequestEvent = RequestEvent>(handlerOptions: OIDCCallbackHandlerOptions<TClaims, TSession> = {}): MinimalRequestHandler<T> {
        return async (event) => {
            try {
                const result = await handleCallback(event);
                const response = await handlerOptions.onsuccess?.(event, result);
                if (response) return response;
                throw redirect(302, internalRedirectPath(event, handlerOptions.redirectTo ?? result.returnTo, '/'));
            } catch (err) {
                const response = await handlerOptions.onfailure?.(event, err);
                if (response) {
                    return response;
                }

                throw err;
            }
        };
    }

    function logoutHandler<T extends MinimalRequestEvent = RequestEvent>(defaults: OIDCLogoutOptions = {}): MinimalRequestHandler<T> {
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

            return signOut(event, {...defaults, postLogoutRedirectUri, clearSessionOnly});
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
                        undefined) ?? undefined;
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

    return {
        handle,
        hook,
        getMetadata,
        getSession,
        getPublicSession: async (event: {
            cookies: RequestEvent['cookies'];
            depends?: (dependency: string) => void;
        }): Promise<OIDCPublicSession<TClaims> | null> => {
            event.depends?.(OIDC_SESSION_REVALIDATION_DEPENDENCY);
            const session = toPublicSession(await getSession(event));

            return session && event.depends
                ? {...session, revalidationDependency: OIDC_SESSION_REVALIDATION_DEPENDENCY}
                : session;
        },
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
