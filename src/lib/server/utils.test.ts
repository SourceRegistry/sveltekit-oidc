import { describe, expect, it } from 'vitest';

import {
	collectGroups,
	normalizeScope,
	parseSignedCookie,
	serializeSignedCookie
} from './utils.js';

describe('normalizeScope', () => {
	it('returns defaults when no scope is provided', () => {
		expect(normalizeScope()).toEqual(['openid', 'profile', 'email']);
	});

	it('deduplicates scope values while preserving order', () => {
		expect(normalizeScope(['openid', 'email', 'openid', 'profile'])).toEqual([
			'openid',
			'email',
			'profile'
		]);
	});
});

describe('collectGroups', () => {
	it('merges groups and roles across sources', () => {
		expect(
			collectGroups(
				{ sub: 'a', groups: ['admin', 'team-a'] },
				{ sub: 'a', roles: ['team-a', 'editor'] } as never
			)
		).toEqual(['admin', 'team-a', 'editor']);
	});
});

describe('signed cookie helpers', () => {
	it('roundtrips payloads', () => {
		const secret = 'test-secret';
		const value = serializeSignedCookie({ sub: 'user-1', groups: ['admin'] }, secret);

		expect(parseSignedCookie<{ sub: string; groups: string[] }>(value, secret)).toEqual({
			sub: 'user-1',
			groups: ['admin']
		});
	});

	it('rejects tampered values', () => {
		const secret = 'test-secret';
		const value = serializeSignedCookie({ sub: 'user-1' }, secret);
		const tampered = `${value}x`;

		expect(parseSignedCookie(tampered, secret)).toBeNull();
	});
});
