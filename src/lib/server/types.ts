import type {Action, Cookies, Handle, RequestEvent} from '@sveltejs/kit';
import type { KeyObject } from 'node:crypto';

export type MaybePromise<T> = Promise<T> | T;

export type SupportedAlgorithm =
	| 'HS256'
	| 'HS384'
	| 'HS512'
	| 'RS256'
	| 'RS384'
	| 'RS512'
	| 'ES256'
	| 'ES384'
	| 'ES512'
	| 'ES256K'
	| 'PS256'
	| 'PS384'
	| 'PS512'
	| 'EdDSA';

export type OIDCDiscoveryDocument = {
	issuer: string;
	authorization_endpoint: string;
	token_endpoint: string;
	userinfo_endpoint?: string;
	end_session_endpoint?: string;
	revocation_endpoint?: string;
	check_session_iframe?: string;
	backchannel_logout_supported?: boolean;
	backchannel_logout_session_supported?: boolean;
	jwks_uri: string;
	response_types_supported?: string[];
	subject_types_supported?: string[];
	id_token_signing_alg_values_supported?: string[];
	scopes_supported?: string[];
	token_endpoint_auth_methods_supported?: string[];
	token_endpoint_auth_signing_alg_values_supported?: string[];
	claims_supported?: string[];
	code_challenge_methods_supported?: string[];
	grant_types_supported?: string[];
};

export type OIDCTokenResponse = {
	access_token: string;
	token_type: string;
	expires_in?: number;
	refresh_token?: string;
	scope?: string;
	id_token?: string;
	refresh_expires_in?: number;
	session_state?: string;
};

export type OIDCSessionTokens = {
	accessToken: string;
	tokenType: string;
	idToken?: string;
	refreshToken?: string;
	scope: string[];
	expiresAt?: number;
	refreshExpiresAt?: number;
};

export type OIDCUserClaims = Record<string, unknown> & {
	sub: string;
	email?: string;
	name?: string;
	preferred_username?: string;
	picture?: string;
	groups?: string[];
	sid?: string;
	iss?: string;
	aud?: string | string[];
	exp?: number;
	iat?: number;
	nbf?: number;
	nonce?: string;
};

export type OIDCSession<TClaims extends OIDCUserClaims = OIDCUserClaims> = {
	issuer: string;
	clientId: string;
	nonce?: string;
	sub?: string;
	sid?: string;
	sessionState?: string;
	groups: string[];
	user?: TClaims;
	claims?: TClaims;
	tokens: OIDCSessionTokens;
	createdAt: number;
	refreshedAt: number;
};

export type OIDCPublicSession<TClaims extends OIDCUserClaims = OIDCUserClaims> = {
	isAuthenticated: boolean;
	user?: TClaims;
	claims?: TClaims;
	groups: string[];
	scope: string[];
	expiresAt?: number;
	issuer?: string;
	sessionState?: string;
	sid?: string;
	sub?: string;
	/** SvelteKit dependency registered by getPublicSession for targeted client revalidation. */
	revalidationDependency?: string;
};

export type OIDCBackChannelLogoutClaims = Record<string, unknown> & {
	iss: string;
	aud: string | string[];
	iat: number;
	jti: string;
	sub?: string;
	sid?: string;
	events: {
		'http://schemas.openid.net/event/backchannel-logout': Record<string, never>;
	};
	nonce?: never;
};

export type OIDCClientAuthMethod =
	| 'client_secret_basic'
	| 'client_secret_post'
	| 'client_secret_jwt'
	| 'private_key_jwt'
	| 'none';

export type CookieOptions = NonNullable<Parameters<Cookies['set']>[2]>;

export type OIDCClientSecretJwtOptions = {
	algorithm?: 'HS256' | 'HS384' | 'HS512';
	expiresInSeconds?: number;
};

export type OIDCPrivateKeyJwtOptions = {
	privateKey: string | KeyObject;
	algorithm?: 'RS256' | 'RS384' | 'RS512';
	keyId?: string;
	expiresInSeconds?: number;
};

export type OIDCBackChannelLogoutRecord = {
	issuer: string;
	clientId: string;
	sid?: string;
	sub?: string;
	jti: string;
	iat: number;
};

export type OIDCBackChannelLogoutStore<
	TClaims extends OIDCUserClaims = OIDCUserClaims,
	TSession extends OIDCSession<TClaims> = OIDCSession<TClaims>
> = {
	revoke(record: OIDCBackChannelLogoutRecord): MaybePromise<void>;
	isRevoked(session: TSession): MaybePromise<boolean>;
};

export type OIDCSessionStore<
	TClaims extends OIDCUserClaims = OIDCUserClaims,
	TSession extends OIDCSession<TClaims> = OIDCSession<TClaims>
> = {
	get(sessionId: string): MaybePromise<TSession | null>;
	set(sessionId: string, session: TSession): MaybePromise<void>;
	delete(sessionId: string): MaybePromise<void>;
};

export type OIDCSessionManagementConfig = {
	clientId: string;
	issuer: string;
	loginPath: string;
	logoutPath: string;
	redirectPath: string;
	metadata: Pick<
		OIDCDiscoveryDocument,
		| 'issuer'
		| 'check_session_iframe'
		| 'end_session_endpoint'
		| 'backchannel_logout_supported'
		| 'backchannel_logout_session_supported'
	>;
	checkSessionIframe?: string;
	supportsSessionIframe: boolean;
	backChannelLogoutSupported: boolean;
	backChannelLogoutSessionSupported: boolean;
};

export type OIDCLogger = {
	debug?: (...args: unknown[]) => void;
	info?: (...args: unknown[]) => void;
	warn?: (...args: unknown[]) => void;
	error?: (...args: unknown[]) => void;
};

export type OIDCOptions<
	TClaims extends OIDCUserClaims = OIDCUserClaims,
	TSession extends OIDCSession<TClaims> = OIDCSession<TClaims>
> = {
	issuer?: string;
	discoveryUrl?: string;
	clientId: string;
	clientSecret?: string;
	clientAuthMethod?: OIDCClientAuthMethod;
	clientSecretJwt?: OIDCClientSecretJwtOptions;
	privateKeyJwt?: OIDCPrivateKeyJwtOptions;
	loginPath?: string;
	logoutPath?: string;
	redirectPath?: string;
	postLogoutRedirectUri?: string;
	scope?: string | string[];
	audience?: string;
	fetchUserInfo?: boolean;
	sessionCookieName?: string;
	stateCookieName?: string;
	cookieSecret: string;
	cookieOptions?: Partial<CookieOptions>;
	clockSkewSeconds?: number;
	refreshToleranceSeconds?: number;
	/** Maximum lifetime of a local browser session. Defaults to 8 hours. */
	sessionMaxAgeSeconds?: number;
	defaultLoginRedirect?: string;
	defaultLogoutRedirect?: string;
	sessionStore?: OIDCSessionStore<TClaims, TSession> | 'memory';
	backChannelLogoutStore?: OIDCBackChannelLogoutStore<TClaims, TSession> | 'memory';
	transformClaims?: (claims: OIDCUserClaims) => MaybePromise<TClaims>;
	transformUser?: (
		user: OIDCUserClaims | undefined,
		context: { claims?: TClaims }
	) => MaybePromise<TClaims | undefined>;
	transformSession?: (
		session: OIDCSession<TClaims>,
		context: {
			event?: MinimalRequestEvent;
			tokenResponse?: OIDCTokenResponse;
			claims?: TClaims;
			user?: TClaims;
			isRefresh: boolean;
		}
	) => MaybePromise<TSession>;
	/**
	 * Runs on every `getSession` read (and therefore every `getPublicSession`,
	 * `hook()`-provided `requireAuth`, and the instance-level `requireAuth`) —
	 * unlike `transformSession`, which only fires on session creation and token
	 * refresh. Use this to keep data your app owns outside the token (e.g. roles
	 * or memberships stored in your own database) fresh without waiting for a
	 * refresh. Only invoked when a session is present; the result is not persisted
	 * back to the session store.
	 */
	enrichSession?: (
		session: TSession,
		context: { event?: MinimalRequestEvent }
	) => MaybePromise<TSession>;
	endpoints?: Partial<OIDCDiscoveryDocument>;
	logger?: OIDCLogger | false;
	/**
	 * Custom fetch implementation used for all OIDC network calls
	 * (discovery, token, userinfo, JWKS). Useful in dev to work around
	 * self-signed certs via a custom https.Agent — do not disable
	 * TLS verification in production.
	 */
	fetch?: typeof fetch;
};

export type OIDCLoginOptions = {
	returnTo?: string;
	prompt?: 'login' | 'consent' | 'none' | 'select_account';
	scope?: string | string[];
	extraParams?: Record<string, string>;
};

export type OIDCLogoutOptions = {
	postLogoutRedirectUri?: string;
	state?: string;
	clearSessionOnly?: boolean;
};

export type OIDCCallbackResult<
	TClaims extends OIDCUserClaims = OIDCUserClaims,
	TSession extends OIDCSession<TClaims> = OIDCSession<TClaims>
> = {
	session: TSession;
	returnTo: string;
};

export type OIDCHandleLocals<
	TClaims extends OIDCUserClaims = OIDCUserClaims,
	TSession extends OIDCSession<TClaims> = OIDCSession<TClaims>
> = {
	isAuthenticated: boolean;
	session: TSession | null;
	user?: TClaims;
	claims?: TClaims;
	requireAuth: () => Promise<TSession>;
	clearSession: () => Promise<void>;
};

export type OIDCStateCookie = {
	state: string;
	nonce: string;
	codeVerifier: string;
	returnTo: string;
	createdAt: number;
};

export type MinimalRequestEvent = { cookies: Cookies, url: URL, request: Request, locals: App.Locals }
export type MinimalRequestHandler<T extends MinimalRequestEvent> = (event: T) => MaybePromise<Response>;


export type OIDCCallbackHandlerOptions<
	TClaims extends OIDCUserClaims = OIDCUserClaims,
	TSession extends OIDCSession<TClaims> = OIDCSession<TClaims>
> = {
	onsuccess?: <T extends MinimalRequestEvent = RequestEvent>(
		event: T,
		result: OIDCCallbackResult<TClaims, TSession>
	) => MaybePromise<Response | void>;
	onfailure?: <T extends MinimalRequestEvent = RequestEvent>(event: T, err: unknown) => MaybePromise<Response | void>;
	redirectTo?: string;
};

export type OIDCActionOptions = {
	defaultReturnTo?: string;
	defaultPostLogoutRedirectUri?: string;
};

export type OIDCClientAssertionOptions = {
	tokenEndpoint: string;
	clientId: string;
	clientSecret?: string;
};

export type OIDCCookies<
	TClaims extends OIDCUserClaims = OIDCUserClaims,
	TSession extends OIDCSession<TClaims> = OIDCSession<TClaims>
> = {
	readSession(cookies: Cookies): TSession | null;
	writeSession(cookies: Cookies, session: TSession): void;
	clearSession(cookies: Cookies): void;
	readSessionReference(cookies: Cookies): { id: string } | null;
	writeSessionReference(cookies: Cookies, reference: { id: string }): void;
	clearSessionReference(cookies: Cookies): void;
	readState(cookies: Cookies): OIDCStateCookie | null;
	writeState(cookies: Cookies, state: OIDCStateCookie): void;
	clearState(cookies: Cookies): void;
};

export type OIDCPersistedSession<
	TClaims extends OIDCUserClaims = OIDCUserClaims,
	TSession extends OIDCSession<TClaims> = OIDCSession<TClaims>
> = {
	id?: string;
	session: TSession;
};

export type OIDCInstance<
	TClaims extends OIDCUserClaims = OIDCUserClaims,
	TSession extends OIDCSession<TClaims> = OIDCSession<TClaims>
> = {
	handle: Handle;
	hook: (event: {cookies: Cookies, locals: App.Locals}) => Promise<{oidc:  OIDCHandleLocals<TClaims, TSession> }>
	getMetadata: () => Promise<OIDCDiscoveryDocument>;
	getSession: (event: {cookies: Cookies}) => Promise<TSession | null>;
	getPublicSession: (event: {
		cookies: Cookies;
		depends?: (dependency: string) => void;
	}) => Promise<OIDCPublicSession<TClaims> | null>;
	getSessionManagementConfig: () => Promise<OIDCSessionManagementConfig>;
	login: (event: MinimalRequestEvent, loginOptions?: OIDCLoginOptions) => Promise<never>;
	logout: (event: MinimalRequestEvent, logoutOptions?: OIDCLogoutOptions) => Promise<never>;
	handleCallback: (event: MinimalRequestEvent) => Promise<OIDCCallbackResult<TClaims, TSession>>;
	handleBackChannelLogout: (event: MinimalRequestEvent) => Promise<Response>;
	loginHandler: <T extends MinimalRequestEvent = RequestEvent>(defaults?: OIDCLoginOptions) => MinimalRequestHandler<T>;
	callbackHandler: <T extends MinimalRequestEvent = RequestEvent>(handlerOptions?: OIDCCallbackHandlerOptions<TClaims, TSession>) => MinimalRequestHandler<T>;
	logoutHandler: <T extends MinimalRequestEvent = RequestEvent>(defaults?: OIDCLogoutOptions) => MinimalRequestHandler<T>;
	backChannelLogoutHandler: <T extends MinimalRequestEvent = RequestEvent>() => MinimalRequestHandler<T>;
	createActions: (actionOptions?: OIDCActionOptions) => Readonly<{
		login: Action;
		logout: Action;
	}>;
	requireAuth: (event: { cookies: Cookies, url: URL }, returnTo?: string) => Promise<TSession>;
	clearSession: (cookies: Cookies) => Promise<void>;
};

export type OIDCInferClaims<T> = T extends OIDCInstance<infer TClaims> ? TClaims : OIDCUserClaims;
export type OIDCInferSession<T> =
	T extends OIDCInstance<infer _TClaims, infer TSession> ? TSession : OIDCSession<OIDCUserClaims>;
export type OIDCLocals<T extends OIDCInstance<any, any>> = OIDCHandleLocals<
	OIDCInferClaims<T>,
	OIDCInferSession<T>
>;
