import type { Action, Cookies, Handle, RequestEvent, RequestHandler } from '@sveltejs/kit';
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
	nbf?: number;
	nonce?: string;
};

export type OIDCSession = {
	issuer: string;
	clientId: string;
	nonce?: string;
	sub?: string;
	sid?: string;
	sessionState?: string;
	groups: string[];
	user?: OIDCUserClaims;
	claims?: OIDCUserClaims;
	tokens: OIDCSessionTokens;
	createdAt: number;
	refreshedAt: number;
};

export type OIDCPublicSession = {
	isAuthenticated: boolean;
	user?: OIDCUserClaims;
	claims?: OIDCUserClaims;
	groups: string[];
	scope: string[];
	expiresAt?: number;
	issuer?: string;
	sessionState?: string;
	sid?: string;
	sub?: string;
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

export type OIDCBackChannelLogoutStore = {
	revoke(record: OIDCBackChannelLogoutRecord): MaybePromise<void>;
	isRevoked(session: OIDCSession): MaybePromise<boolean>;
};

export type OIDCSessionStore = {
	get(sessionId: string): MaybePromise<OIDCSession | null>;
	set(sessionId: string, session: OIDCSession): MaybePromise<void>;
	delete(sessionId: string): MaybePromise<void>;
};

export type OIDCSessionManagementConfig = {
	clientId: string;
	loginPath: string;
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

export type OIDCOptions = {
	issuer?: string;
	discoveryUrl?: string;
	clientId: string;
	clientSecret?: string;
	clientAuthMethod?: OIDCClientAuthMethod;
	clientSecretJwt?: OIDCClientSecretJwtOptions;
	privateKeyJwt?: OIDCPrivateKeyJwtOptions;
	loginPath?: string;
	redirectPath?: string;
	postLogoutRedirectUri?: string;
	scope?: string[];
	audience?: string;
	fetchUserInfo?: boolean;
	sessionCookieName?: string;
	stateCookieName?: string;
	cookieSecret: string;
	cookieOptions?: Partial<CookieOptions>;
	refreshToleranceSeconds?: number;
	defaultLoginRedirect?: string;
	defaultLogoutRedirect?: string;
	sessionStore?: OIDCSessionStore;
	backChannelLogoutStore?: OIDCBackChannelLogoutStore;
	transformClaims?: (claims: OIDCUserClaims) => MaybePromise<OIDCUserClaims>;
	transformUser?: (
		user: OIDCUserClaims | undefined,
		context: { claims?: OIDCUserClaims }
	) => MaybePromise<OIDCUserClaims | undefined>;
	transformSession?: (
		session: OIDCSession,
		context: {
			event?: RequestEvent;
			tokenResponse?: OIDCTokenResponse;
			claims?: OIDCUserClaims;
			user?: OIDCUserClaims;
			isRefresh: boolean;
		}
	) => MaybePromise<OIDCSession>;
	endpoints?: Partial<OIDCDiscoveryDocument>;
};

export type OIDCLoginOptions = {
	returnTo?: string;
	prompt?: 'login' | 'consent' | 'none' | 'select_account';
	scope?: string[];
	extraParams?: Record<string, string>;
};

export type OIDCLogoutOptions = {
	postLogoutRedirectUri?: string;
	state?: string;
	clearSessionOnly?: boolean;
};

export type OIDCCallbackResult = {
	session: OIDCSession;
	returnTo: string;
};

export type OIDCHandleLocals = {
	isAuthenticated: boolean;
	session: OIDCSession | null;
	user?: OIDCUserClaims;
	claims?: OIDCUserClaims;
	requireAuth: () => Promise<OIDCSession>;
	clearSession: () => Promise<void>;
};

export type OIDCStateCookie = {
	state: string;
	nonce: string;
	codeVerifier: string;
	returnTo: string;
	createdAt: number;
};

export type OIDCCallbackHandlerOptions = {
	onsuccess?: (event: RequestEvent, result: OIDCCallbackResult) => MaybePromise<Response | void>;
	onfailure?: (event: RequestEvent, err: unknown) => MaybePromise<Response | void>;
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

export type OIDCCookies = {
	readSession(cookies: Cookies): OIDCSession | null;
	writeSession(cookies: Cookies, session: OIDCSession): void;
	clearSession(cookies: Cookies): void;
	readSessionReference(cookies: Cookies): { id: string } | null;
	writeSessionReference(cookies: Cookies, reference: { id: string }): void;
	clearSessionReference(cookies: Cookies): void;
	readState(cookies: Cookies): OIDCStateCookie | null;
	writeState(cookies: Cookies, state: OIDCStateCookie): void;
	clearState(cookies: Cookies): void;
};

export type OIDCPersistedSession = {
	id?: string;
	session: OIDCSession;
};

export type OIDCInstance = {
	handle: Handle;
	getMetadata: () => Promise<OIDCDiscoveryDocument>;
	getSession: (event: RequestEvent) => Promise<OIDCSession | null>;
	getPublicSession: (event: RequestEvent) => Promise<OIDCPublicSession | null>;
	getSessionManagementConfig: () => Promise<OIDCSessionManagementConfig>;
	login: (event: RequestEvent, loginOptions?: OIDCLoginOptions) => Promise<never>;
	logout: (event: RequestEvent, logoutOptions?: OIDCLogoutOptions) => Promise<never>;
	handleCallback: (event: RequestEvent) => Promise<OIDCCallbackResult>;
	handleBackChannelLogout: (event: RequestEvent) => Promise<Response>;
	loginHandler: (defaults?: OIDCLoginOptions) => RequestHandler;
	callbackHandler: (handlerOptions?: OIDCCallbackHandlerOptions) => RequestHandler;
	logoutHandler: (defaults?: OIDCLogoutOptions) => RequestHandler;
	backChannelLogoutHandler: () => RequestHandler;
	createActions: (actionOptions?: OIDCActionOptions) => Readonly<{
		login: Action;
		logout: Action;
	}>;
	requireAuth: (event: RequestEvent, returnTo?: string) => Promise<OIDCSession>;
	clearSession: (cookies: Cookies) => Promise<void>;
};
