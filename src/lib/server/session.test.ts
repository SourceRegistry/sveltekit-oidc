import {describe, expect, it} from 'vitest';

import {isSessionExpired, normalizeTokens, shouldRefresh} from './session.js';
import type {OIDCSession} from './types.js';

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
			idTokenClaims: {sub: 'user-1'},
			identity: {sub: 'user-1'},
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
			idTokenClaims: {sub: 'user-1'},
			identity: {sub: 'user-1'},
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

describe('isSessionExpired', () => {
	const session = {
		issuer: 'https://issuer.example',
		clientId: 'client',
		groups: [],
		idTokenClaims: {sub: 'user-1'},
		identity: {sub: 'user-1'},
		tokens: {accessToken: 'access', tokenType: 'Bearer', scope: ['openid']},
		createdAt: 100,
		refreshedAt: 100
	} satisfies OIDCSession;

	it('enforces the local session maximum age', () => {
		expect(isSessionExpired(session, 300, 399)).toBe(false);
		expect(isSessionExpired(session, 300, 400)).toBe(true);
	});

	it('expires an unrefreshable session with its access token', () => {
		const unrefreshableSession = {
			...session,
			tokens: {...session.tokens, expiresAt: 200}
		};

		expect(isSessionExpired(unrefreshableSession, 1000, 199)).toBe(false);
		expect(isSessionExpired(unrefreshableSession, 1000, 200)).toBe(true);
	});
});
