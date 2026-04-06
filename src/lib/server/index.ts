import {
	error,
	redirect,
	type Action,
	type Handle,
	type RequestEvent,
	type RequestHandler
} from '@sveltejs/kit';
import { randomBytes } from 'node:crypto';
import { decode, fromWeb, verify } from '@sourceregistry/node-jwt/promises';
import type { JWKSResolver, JWT as JSONWebToken } from '@sourceregistry/node-jwt';

import { createOIDCCookieStore } from './cookies.js';
import {
	asAuthorizationHeader,
	createClientSecretJwtAssertion,
	createPrivateKeyJwtAssertion,
	fetchJson
} from './jwt.js';
import { normalizeTokens, shouldRefresh } from './session.js';
import type {
	OIDCActionOptions,
	OIDCBackChannelLogoutClaims,
	OIDCCallbackHandlerOptions,
	OIDCCallbackResult,
	OIDCClientAuthMethod,
	OIDCDiscoveryDocument,
	OIDCHandleLocals,
	OIDCLoginOptions,
	OIDCLogoutOptions,
	OIDCOptions,
	OIDCInstance,
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
	normalizeIssuer,
	normalizeScope,
	parseProviderError,
	toPublicSession
} from './utils.js';

export type * from './types.js';
export { createInMemoryBackChannelLogoutStore } from './store.js';

export function createOIDC(options: OIDCOptions): OIDCInstance {
	const cookieOptions = buildCookieOptions(options.cookieOptions);
	const refreshToleranceSeconds = options.refreshToleranceSeconds ?? 30;
	const sessionCookieName = options.sessionCookieName ?? 'oidc_session';
	const stateCookieName = options.stateCookieName ?? 'oidc_auth_state';
	const defaultScope = normalizeScope(options.scope);
	const loginPath = options.loginPath ?? '/auth/login';
	const redirectPath = options.redirectPath ?? '/auth/callback';
	const clientAuthMethod: OIDCClientAuthMethod =
		options.clientAuthMethod ?? (options.clientSecret ? 'client_secret_basic' : 'none');

	const cookieStore = createOIDCCookieStore(
		options.cookieSecret,
		sessionCookieName,
		stateCookieName,
		cookieOptions
	);

	let metadataPromise: Promise<OIDCDiscoveryDocument> | undefined;
	let jwksPromise: Promise<JWKSResolver> | undefined;

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
					throw error(500, { message: 'OIDC issuer or discoveryUrl must be configured' });
				}

				const document = await fetchJson<OIDCDiscoveryDocument>(discoveryUrl);
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
					throw error(500, { message: 'OIDC jwks_uri is required to validate id_token values' });
				}

				return fromWeb(metadata.jwks_uri, { overrideEndpointCheck: true });
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
		}
	): Promise<T> {
		let decoded: JSONWebToken;
		try {
			decoded = await decode(token);
		} catch {
			throw error(400, { message: 'Invalid JWT format' });
		}

		const jwks = await getJwks();
		const key = decoded.header.kid ? await jwks.key(decoded.header.kid) : (await jwks.list())[0];
		if (!key) {
			throw error(401, { message: 'Unable to resolve a signing key from JWKS' });
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
				return { headers, body };
			case 'client_secret_basic':
				if (!options.clientSecret) {
					throw error(500, { message: 'clientSecret is required for client_secret_basic' });
				}
				headers.authorization = asAuthorizationHeader(options.clientId, options.clientSecret);
				return { headers, body };
			case 'client_secret_post':
				if (!options.clientSecret) {
					throw error(500, { message: 'clientSecret is required for client_secret_post' });
				}
				body.set('client_id', options.clientId);
				body.set('client_secret', options.clientSecret);
				return { headers, body };
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
				return { headers, body };
			case 'private_key_jwt':
				if (!options.privateKeyJwt?.privateKey) {
					throw error(500, { message: 'privateKeyJwt.privateKey is required for private_key_jwt' });
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
				return { headers, body };
			default:
				throw error(500, { message: `Unsupported client authentication method '${clientAuthMethod}'` });
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
		});
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
		});
	}

	async function validateIdToken(idToken: string, nonce: string) {
		const metadata = await getMetadata();
		const claims = await verifyJwtWithJwks<OIDCUserClaims>(idToken, {
			issuer: metadata.issuer,
			audience: options.clientId,
			algorithms: metadata.id_token_signing_alg_values_supported as SupportedAlgorithm[] | undefined
		});
		const transformedClaims = options.transformClaims ? await options.transformClaims(claims) : claims;
		if (transformedClaims.nonce !== nonce) {
			throw error(401, { message: 'Invalid id_token nonce' });
		}

		return transformedClaims;
	}

	async function validateBackChannelLogoutToken(logoutToken: string) {
		const metadata = await getMetadata();
		const claims = await verifyJwtWithJwks<OIDCBackChannelLogoutClaims>(logoutToken, {
			issuer: metadata.issuer,
			audience: options.clientId
		});
		if (!claims.events?.['http://schemas.openid.net/event/backchannel-logout']) {
			throw error(400, { message: 'Invalid logout_token events claim' });
		}
		if (!claims.sid && !claims.sub) {
			throw error(400, { message: 'logout_token must contain sid or sub' });
		}
		if ('nonce' in claims && claims.nonce !== undefined) {
			throw error(400, { message: 'logout_token must not contain nonce' });
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
		});
	}

	async function isRevoked(session: OIDCSession | null) {
		if (!session || !options.backChannelLogoutStore) {
			return false;
		}

		return options.backChannelLogoutStore.isRevoked(session);
	}

	async function maybeRefreshSession(event: RequestEvent, session: OIDCSession | null) {
		if (!session) {
			return null;
		}
		if (await isRevoked(session)) {
			cookieStore.clearSession(event.cookies);
			return null;
		}
		if (!shouldRefresh(session, refreshToleranceSeconds)) {
			return session;
		}

		try {
			const tokenResponse = await refreshTokens(session.tokens.refreshToken as string);
			const claims = tokenResponse.id_token
				? await validateIdToken(tokenResponse.id_token, session.nonce as string)
				: session.claims;
			const rawUser =
				options.fetchUserInfo !== false ? await fetchUserInfo(tokenResponse.access_token) : session.user;
			const user = options.transformUser ? await options.transformUser(rawUser, { claims }) : rawUser;
			const nextSession: OIDCSession = {
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
				: nextSession;
			cookieStore.writeSession(event.cookies, finalSession);
			return finalSession;
		} catch {
			cookieStore.clearSession(event.cookies);
			return null;
		}
	}

	async function getSession(event: RequestEvent) {
		return maybeRefreshSession(event, cookieStore.readSession(event.cookies));
	}

	async function signIn(event: RequestEvent, loginOptions: OIDCLoginOptions = {}): Promise<never> {
		const metadata = await getMetadata();
		const pkce = createPKCEPair();
		const state = base64UrlEncode(randomBytes(24));
		const nonce = base64UrlEncode(randomBytes(24));
		const returnTo = loginOptions.returnTo ?? options.defaultLoginRedirect ?? '/';

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

	async function handleCallback(event: RequestEvent): Promise<OIDCCallbackResult> {
		const providerError = parseProviderError(event);
		if (providerError) {
			throw providerError;
		}

		const stateCookie = cookieStore.readState(event.cookies);
		const state = event.url.searchParams.get('state');
		const code = event.url.searchParams.get('code');

		if (!stateCookie || !state || !code || stateCookie.state !== state) {
			cookieStore.clearState(event.cookies);
			throw error(400, { message: 'Invalid or expired OIDC callback state' });
		}

		cookieStore.clearState(event.cookies);

		const tokenResponse = await exchangeCode({
			code,
			redirectUri: absoluteUrl(event, redirectPath),
			codeVerifier: stateCookie.codeVerifier
		});

		const claims = tokenResponse.id_token
			? await validateIdToken(tokenResponse.id_token, stateCookie.nonce)
			: undefined;
		const rawUser =
			options.fetchUserInfo === false
				? undefined
				: await fetchUserInfo(tokenResponse.access_token).catch(() => undefined);
		const user = options.transformUser ? await options.transformUser(rawUser, { claims }) : rawUser;
		const metadata = await getMetadata();
		const now = Math.floor(Date.now() / 1000);
		const session: OIDCSession = {
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
					event,
					tokenResponse,
					claims,
					user,
					isRefresh: false
				})
			: session;

		cookieStore.writeSession(event.cookies, finalSession);

		return {
			session: finalSession,
			returnTo: stateCookie.returnTo
		};
	}

	async function signOut(event: RequestEvent, logoutOptions: OIDCLogoutOptions = {}): Promise<never> {
		const metadata = await getMetadata();
		const session = cookieStore.readSession(event.cookies);
		cookieStore.clearState(event.cookies);
		cookieStore.clearSession(event.cookies);

		if (logoutOptions.clearSessionOnly || !metadata.end_session_endpoint) {
			throw redirect(
				302,
				logoutOptions.postLogoutRedirectUri ??
					options.defaultLogoutRedirect ??
					options.postLogoutRedirectUri ??
					'/'
			);
		}

		const url = new URL(metadata.end_session_endpoint);
		if (session?.tokens.idToken) {
			url.searchParams.set('id_token_hint', session.tokens.idToken);
		}
		url.searchParams.set(
			'post_logout_redirect_uri',
			absoluteUrl(
				event,
				logoutOptions.postLogoutRedirectUri ??
					options.postLogoutRedirectUri ??
					options.defaultLogoutRedirect ??
					'/'
			)
		);
		if (logoutOptions.state) {
			url.searchParams.set('state', logoutOptions.state);
		}

		throw redirect(302, url.toString());
	}

	async function handleBackChannelLogout(event: RequestEvent) {
		const metadata = await getMetadata();
		if (!metadata.backchannel_logout_supported) {
			throw error(400, { message: 'Provider does not advertise back-channel logout support' });
		}
		if (!options.backChannelLogoutStore) {
			throw error(500, {
				message: 'backChannelLogoutStore is required for back-channel logout with cookie sessions'
			});
		}

		const form = await event.request.formData();
		const logoutToken = form.get('logout_token')?.toString();
		if (!logoutToken) {
			throw error(400, { message: 'logout_token is required' });
		}

		const claims = await validateBackChannelLogoutToken(logoutToken);
		await options.backChannelLogoutStore.revoke({
			issuer: claims.iss,
			clientId: options.clientId,
			sid: claims.sid,
			sub: claims.sub,
			jti: claims.jti,
			iat: claims.iat
		});

		return new Response(null, { status: 200 });
	}

	function requireAuth(event: RequestEvent, returnTo?: string) {
		const session = cookieStore.readSession(event.cookies);
		if (session) {
			return session;
		}

		throw redirect(
			302,
			`${absoluteUrl(event, loginPath)}?returnTo=${encodeURIComponent(
				returnTo ?? `${event.url.pathname}${event.url.search}`
			)}`
		);
	}

	const handle: Handle = async ({ event, resolve }) => {
		const session = await getSession(event);
		(event.locals as { oidc?: OIDCHandleLocals }).oidc = {
			isAuthenticated: Boolean(session),
			session,
			user: session?.user,
			claims: session?.claims,
			requireAuth: () => {
				if (!session) {
					throw error(401, { message: 'Authentication required' });
				}
			},
			clearSession: () => cookieStore.clearSession(event.cookies)
		};

		return resolve(event);
	};

	function loginHandler(defaults: OIDCLoginOptions = {}): RequestHandler {
		return async (event) => {
			const returnTo = event.url.searchParams.get('returnTo') ?? defaults.returnTo;
			return signIn(event, { ...defaults, returnTo });
		};
	}

	function callbackHandler(handlerOptions: OIDCCallbackHandlerOptions = {}): RequestHandler {
		return async (event) => {
			try {
				const result = await handleCallback(event);
				const response = await handlerOptions.onsuccess?.(event, result);
				if (response) {
					return response;
				}

				throw redirect(302, handlerOptions.redirectTo ?? result.returnTo);
			} catch (err) {
				const response = await handlerOptions.onfailure?.(event, err);
				if (response) {
					return response;
				}

				throw err;
			}
		};
	}

	function logoutHandler(defaults: OIDCLogoutOptions = {}): RequestHandler {
		return async (event) => {
			const postLogoutRedirectUri =
				event.url.searchParams.get('postLogoutRedirectUri') ?? defaults.postLogoutRedirectUri;
			const clearSessionOnly =
				event.url.searchParams.get('clearSessionOnly') === '1' ||
				event.url.searchParams.get('clearSessionOnly') === 'true' ||
				defaults.clearSessionOnly;

			return signOut(event, { ...defaults, postLogoutRedirectUri, clearSessionOnly });
		};
	}

	function backChannelLogoutHandler(): RequestHandler {
		return async (event) => handleBackChannelLogout(event);
	}

	function createActions(actionOptions: OIDCActionOptions = {}) {
		return {
			login: (async (event: RequestEvent) => {
				const form = await event.request.formData();
				const returnTo =
					(form.get('returnTo')?.toString() || actionOptions.defaultReturnTo || undefined) ?? undefined;

				return signIn(event, { returnTo });
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

				return signOut(event, { postLogoutRedirectUri, clearSessionOnly });
			}) satisfies Action
		} as const;
	}

	async function getSessionManagementConfig(): Promise<OIDCSessionManagementConfig> {
		const metadata = await getMetadata();
		return {
			clientId: options.clientId,
			loginPath,
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
		getMetadata,
		getSession,
		getPublicSession: async (event: RequestEvent): Promise<OIDCPublicSession | null> =>
			toPublicSession(await getSession(event)),
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
		clearSession: cookieStore.clearSession
	};
}

export const OpenIDConnect = createOIDC;
