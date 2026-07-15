import {isRedirect, type Cookies} from '@sveltejs/kit';
import {describe, expect, it, vi} from 'vitest';

import {createOIDC} from './index.js';
import {serializeSignedCookie} from './utils.js';
import type {OIDCSession} from './types.js';

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

		await oidc.getPublicSession({cookies: createCookies(), depends});

		expect(depends).toHaveBeenCalledOnce();
		expect(depends).toHaveBeenCalledWith('oidc:session');
	});

	it('projects an already loaded session without reading or enriching it again', () => {
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

		const result = oidc.toPublicSession(session, depends);

		expect(loadRequestData).not.toHaveBeenCalled();
		expect(depends).toHaveBeenCalledWith('oidc:session');
		expect(result).toMatchObject({
			isAuthenticated: true,
			sub: 'user-1',
			groups: ['admin'],
			revalidationDependency: 'oidc:session'
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
