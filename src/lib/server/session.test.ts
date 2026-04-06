import { describe, expect, it } from 'vitest';

import { normalizeTokens, shouldRefresh } from './session.js';
import type { OIDCSession } from './types.js';

describe('normalizeTokens', () => {
	it('merges token responses with existing tokens', () => {
		expect(
			normalizeTokens(
				{
					access_token: 'new-access',
					token_type: 'Bearer',
					expires_in: 300
				},
				['openid', 'profile'],
				{
					accessToken: 'old-access',
					tokenType: 'Bearer',
					idToken: 'id-token',
					refreshToken: 'refresh-token',
					scope: ['openid'],
					expiresAt: 10,
					refreshExpiresAt: 20
				},
				100
			)
		).toEqual({
			accessToken: 'new-access',
			tokenType: 'Bearer',
			idToken: 'id-token',
			refreshToken: 'refresh-token',
			scope: ['openid'],
			expiresAt: 400,
			refreshExpiresAt: 20
		});
	});
});

describe('shouldRefresh', () => {
	it('returns false without refresh capability', () => {
		const session = {
			issuer: 'https://issuer.example',
			clientId: 'client',
			groups: [],
			tokens: {
				accessToken: 'access',
				tokenType: 'Bearer',
				scope: ['openid']
			},
			createdAt: 0,
			refreshedAt: 0
		} satisfies OIDCSession;

		expect(shouldRefresh(session, 30, 100)).toBe(false);
	});

	it('returns true inside the refresh tolerance window', () => {
		const session = {
			issuer: 'https://issuer.example',
			clientId: 'client',
			groups: [],
			tokens: {
				accessToken: 'access',
				tokenType: 'Bearer',
				refreshToken: 'refresh',
				scope: ['openid'],
				expiresAt: 120
			},
			createdAt: 0,
			refreshedAt: 0
		} satisfies OIDCSession;

		expect(shouldRefresh(session, 30, 91)).toBe(true);
		expect(shouldRefresh(session, 30, 80)).toBe(false);
	});
});
