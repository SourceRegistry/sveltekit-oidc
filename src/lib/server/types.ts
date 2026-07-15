import type {Action, Cookies, Handle, RequestEvent} from '@sveltejs/kit';
import type {KeyObject} from 'node:crypto';

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

export type OIDCSessionReason = 'login' | 'refresh';

export type OIDCSession<TIdentity extends OIDCUserClaims = OIDCUserClaims> = {
	issuer: string;
	clientId: string;
	nonce?: string;
	sub?: string;
	sid?: string;
	sessionState?: string;
	groups: string[];
	/** Validated claims from the ID token. */
	idTokenClaims: OIDCUserClaims;
	/** Raw response from the UserInfo endpoint, when requested. */
	userInfo?: OIDCUserClaims;
	/** Application-facing identity resolved from the validated provider data. */
	identity: TIdentity;
	tokens: OIDCSessionTokens;
	createdAt: number;
	refreshedAt: number;
};

export type OIDCPublicSession<TIdentity extends OIDCUserClaims = OIDCUserClaims> = {
	isAuthenticated: boolean;
	identity: TIdentity;
	groups: string[];
	scope: string[];
	expiresAt?: number;
	issuer?: string;
	sessionState?: string;
	sid?: string;
	sub?: string;
	/** SvelteKit dependency registered during public projection for targeted client revalidation. */
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
	'client_secret_basic' | 'client_secret_post' | 'client_secret_jwt' | 'private_key_jwt' | 'none';

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

export type OIDCBackChannelLogoutStore<TIdentity extends OIDCUserClaims = OIDCUserClaims> = {
	revoke(record: OIDCBackChannelLogoutRecord): MaybePromise<void>;
	isRevoked(session: OIDCSession<TIdentity>): MaybePromise<boolean>;
};

export type OIDCSessionStore<TIdentity extends OIDCUserClaims = OIDCUserClaims> = {
	get(sessionId: string): MaybePromise<OIDCSession<TIdentity> | null>;
	set(sessionId: string, session: OIDCSession<TIdentity>): MaybePromise<void>;
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

export type OIDCOptions<TIdentity extends OIDCUserClaims = OIDCUserClaims, TRequestData = undefined> = {
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
	sessionStore?: OIDCSessionStore<TIdentity> | 'memory';
	backChannelLogoutStore?: OIDCBackChannelLogoutStore<TIdentity> | 'memory';
	/** Resolves application identity after provider data validation on login and refresh. */
	resolveIdentity?: (context: {
		idTokenClaims: OIDCUserClaims;
		userInfo?: OIDCUserClaims;
		reason: OIDCSessionReason;
	}) => MaybePromise<TIdentity>;
	/** Runs immediately before a login or refreshed session is persisted. */
	beforeSessionPersist?: (context: {
		session: OIDCSession<TIdentity>;
		reason: OIDCSessionReason;
		event?: MinimalRequestEvent;
		tokenResponse: OIDCTokenResponse;
	}) => MaybePromise<void>;
	/**
	 * Loads application-owned data once for each authenticated request handled by
	 * `handle`. The result is exposed as `event.locals.oidc.data` and is never
	 * persisted in the OIDC session.
	 */
	loadRequestData?: (context: {
		session: OIDCSession<TIdentity>;
		event: MinimalRequestEvent;
	}) => MaybePromise<TRequestData>;
	/**
	 * Creates the browser-safe session from persisted authentication and
	 * request-only application data. Runs only when a public session is requested.
	 */
	createPublicSession?: (context: {
		session: OIDCSession<TIdentity>;
		data: TRequestData | null;
		base: OIDCPublicSession<TIdentity>;
	}) => OIDCPublicSession<TIdentity>;
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

export type OIDCCallbackResult<TIdentity extends OIDCUserClaims = OIDCUserClaims> = {
	session: OIDCSession<TIdentity>;
	returnTo: string;
};

export type OIDCHandleLocals<TIdentity extends OIDCUserClaims = OIDCUserClaims, TRequestData = undefined> = {
	isAuthenticated: boolean;
	session: OIDCSession<TIdentity> | null;
	identity?: TIdentity;
	data: TRequestData | null;
	requireAuth: () => Promise<OIDCSession<TIdentity>>;
	clearSession: () => Promise<void>;
};

export type OIDCStateCookie = {
	state: string;
	nonce: string;
	codeVerifier: string;
	returnTo: string;
	createdAt: number;
};

export type MinimalRequestEvent = {
	cookies: Cookies;
	url: URL;
	request: Request;
	locals: App.Locals;
};
export type MinimalRequestHandler<T extends MinimalRequestEvent> = (event: T) => MaybePromise<Response>;

export type OIDCCallbackHandlerOptions<TIdentity extends OIDCUserClaims = OIDCUserClaims> = {
	onsuccess?: <T extends MinimalRequestEvent = RequestEvent>(
		event: T,
		result: OIDCCallbackResult<TIdentity>
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

export type OIDCCookies<TIdentity extends OIDCUserClaims = OIDCUserClaims> = {
	readSession(cookies: Cookies): OIDCSession<TIdentity> | null;
	writeSession(cookies: Cookies, session: OIDCSession<TIdentity>): void;
	clearSession(cookies: Cookies): void;
	readSessionReference(cookies: Cookies): {id: string} | null;
	writeSessionReference(cookies: Cookies, reference: {id: string}): void;
	clearSessionReference(cookies: Cookies): void;
	readState(cookies: Cookies): OIDCStateCookie | null;
	writeState(cookies: Cookies, state: OIDCStateCookie): void;
	clearState(cookies: Cookies): void;
};

export type OIDCPersistedSession<TIdentity extends OIDCUserClaims = OIDCUserClaims> = {
	id?: string;
	session: OIDCSession<TIdentity>;
};

export type OIDCInstance<TIdentity extends OIDCUserClaims = OIDCUserClaims, TRequestData = undefined> = {
	handle: Handle;
	createRequestContext: (event: MinimalRequestEvent) => Promise<OIDCHandleLocals<TIdentity, TRequestData>>;
	getMetadata: () => Promise<OIDCDiscoveryDocument>;
	getSession: (event: {cookies: Cookies}) => Promise<OIDCSession<TIdentity> | null>;
	getPublicSession: (
		event: MinimalRequestEvent & {
			depends?: (dependency: string) => void;
		}
	) => Promise<OIDCPublicSession<TIdentity> | null>;
	/** Projects an already-loaded request context without repeating any server work. */
	toPublicSession: (
		context: OIDCHandleLocals<TIdentity, TRequestData> | null | undefined,
		depends?: (dependency: string) => void
	) => OIDCPublicSession<TIdentity> | null;
	getSessionManagementConfig: () => Promise<OIDCSessionManagementConfig>;
	login: (event: MinimalRequestEvent, loginOptions?: OIDCLoginOptions) => Promise<never>;
	logout: (event: MinimalRequestEvent, logoutOptions?: OIDCLogoutOptions) => Promise<never>;
	handleCallback: (event: MinimalRequestEvent) => Promise<OIDCCallbackResult<TIdentity>>;
	handleBackChannelLogout: (event: MinimalRequestEvent) => Promise<Response>;
	loginHandler: <T extends MinimalRequestEvent = RequestEvent>(
		defaults?: OIDCLoginOptions
	) => MinimalRequestHandler<T>;
	callbackHandler: <T extends MinimalRequestEvent = RequestEvent>(
		handlerOptions?: OIDCCallbackHandlerOptions<TIdentity>
	) => MinimalRequestHandler<T>;
	logoutHandler: <T extends MinimalRequestEvent = RequestEvent>(
		defaults?: OIDCLogoutOptions
	) => MinimalRequestHandler<T>;
	backChannelLogoutHandler: <T extends MinimalRequestEvent = RequestEvent>() => MinimalRequestHandler<T>;
	createActions: (actionOptions?: OIDCActionOptions) => Readonly<{
		login: Action;
		logout: Action;
	}>;
	requireAuth: (event: {cookies: Cookies; url: URL}, returnTo?: string) => Promise<OIDCSession<TIdentity>>;
	clearSession: (cookies: Cookies) => Promise<void>;
};

export type OIDCInferIdentity<T> = T extends OIDCInstance<infer TIdentity, any> ? TIdentity : OIDCUserClaims;
export type OIDCInferRequestData<T> = T extends OIDCInstance<any, infer TRequestData> ? TRequestData : undefined;
export type OIDCInferSession<T> = OIDCSession<OIDCInferIdentity<T>>;
export type OIDCLocals<T extends OIDCInstance<any, any>> = OIDCHandleLocals<
	OIDCInferIdentity<T>,
	OIDCInferRequestData<T>
>;
