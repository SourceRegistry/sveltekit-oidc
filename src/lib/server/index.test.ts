import {isRedirect, type Cookies} from '@sveltejs/kit';
import {describe, expect, it, vi} from 'vitest';

import {createOIDC} from './index.js';

const createCookies = (): Cookies =>
	({
		get: vi.fn(() => undefined),
		getAll: vi.fn(() => []),
		set: vi.fn(),
		delete: vi.fn(),
		serialize: vi.fn()
	}) as unknown as Cookies;

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
		const handler = oidc.logoutHandler({postLogoutRedirectUri: '/signed-out'});
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
			expect(location.searchParams.get('post_logout_redirect_uri')).toBe(
				'https://app.example/signed-out'
			);
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
});
