import {isRedirect, type Cookies} from '@sveltejs/kit';
import {describe, expect, it, vi} from 'vitest';

import {createOIDC} from './index.js';
import {serializeSignedCookie} from './utils.js';
import type {OIDCHandleLocals, OIDCSession, OIDCStateCookie, OIDCUserClaims} from './types.js';

const createCookies = (): Cookies =>
	({
		get: vi.fn(() => undefined),
		getAll: vi.fn(() => []),
		set: vi.fn(),
		delete: vi.fn(),
		serialize: vi.fn()
	}) as unknown as Cookies;

const cookieSecret = 'test-cookie-secret';

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
			cookieSecret: 'test-cookie-secret',
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
			await handler({cookies: createCookiesWithSession(session), request: new Request(url), url} as never);
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
		const url = new URL(
			'https://app.example/auth/callback?error=login_required&state=silent-state'
		);

		const response = await handler({cookies, request: new Request(url), url} as never);
		expect(response.status).toBe(200);
		expect(await response.text()).toContain('data-oidc-silent-reauth="logged_out"');
		expect(cookies.delete).toHaveBeenCalledWith('oidc_session', expect.any(Object));
		expect(cookies.delete).toHaveBeenCalledWith('oidc_auth_state', expect.any(Object));
	});
});

describe('OIDC public session revalidation', () => {
	it('registers a targeted SvelteKit dependency when depends is available', async () => {
		const oidc = createOIDC({
			issuer: 'https://identity.example/realms/test',
			clientId: 'client-app',
			cookieSecret: 'test-cookie-secret',
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
		expect(result?.identity).toEqual({sub: 'user-1', permissions: ['read', 'write']});
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
