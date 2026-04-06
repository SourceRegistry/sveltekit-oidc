import { describe, expect, it } from 'vitest';

import { createInMemoryBackChannelLogoutStore } from './store.js';

describe('createInMemoryBackChannelLogoutStore', () => {
	it('revokes by sid', async () => {
		const store = createInMemoryBackChannelLogoutStore();

		await store.revoke({
			issuer: 'https://issuer.example',
			clientId: 'client',
			sid: 'sid-1',
			jti: 'jti-1',
			iat: 1
		});

		await expect(
			store.isRevoked({
				issuer: 'https://issuer.example',
				clientId: 'client',
				sid: 'sid-1',
				groups: [],
				tokens: {
					accessToken: 'access',
					tokenType: 'Bearer',
					scope: ['openid']
				},
				createdAt: 0,
				refreshedAt: 0
			})
		).resolves.toBe(true);
	});

	it('revokes by sub', async () => {
		const store = createInMemoryBackChannelLogoutStore();

		await store.revoke({
			issuer: 'https://issuer.example',
			clientId: 'client',
			sub: 'user-1',
			jti: 'jti-1',
			iat: 1
		});

		await expect(
			store.isRevoked({
				issuer: 'https://issuer.example',
				clientId: 'client',
				sub: 'user-1',
				groups: [],
				tokens: {
					accessToken: 'access',
					tokenType: 'Bearer',
					scope: ['openid']
				},
				createdAt: 0,
				refreshedAt: 0
			})
		).resolves.toBe(true);
	});
});
