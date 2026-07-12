import { describe, expect, it } from 'vitest';

import {
	collectGroups,
	createSignedValue,
	internalRedirectPath,
	normalizeScope,
	parseSignedCookie,
	serializeSignedCookie,
	validateIdTokenClaims,
	validateUserInfoSubject
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

	it('does not expose plaintext payload data', () => {
		const value = serializeSignedCookie({ refreshToken: 'secret-refresh-token' }, 'test-secret');

		expect(value).not.toContain('secret-refresh-token');
		expect(value.startsWith('v2.')).toBe(true);
	});

	it('rejects tampered values', () => {
		const secret = 'test-secret';
		const value = serializeSignedCookie({ sub: 'user-1' }, secret);
		const tampered = `${value}x`;

		expect(parseSignedCookie(tampered, secret)).toBeNull();
	});

	it('rejects legacy signed-only values', () => {
		const secret = 'test-secret';
		const value = createSignedValue(Buffer.from(JSON.stringify({ sub: 'user-1' })).toString('base64url'), secret);

		expect(parseSignedCookie(value, secret)).toBeNull();
	});
});

describe('internalRedirectPath', () => {
	const event = {
		url: new URL('https://app.example.test/current?x=1')
	} as never;

	it('keeps same-origin paths relative', () => {
		expect(internalRedirectPath(event, '/account?tab=settings#profile')).toBe(
			'/account?tab=settings#profile'
		);
	});

	it('normalizes same-origin absolute URLs to paths', () => {
		expect(internalRedirectPath(event, 'https://app.example.test/account')).toBe('/account');
	});

	it('rejects external redirects', () => {
		expect(internalRedirectPath(event, 'https://attacker.example.test/phish', '/')).toBe('/');
		expect(internalRedirectPath(event, '//attacker.example.test/phish', '/')).toBe('/');
	});
});

describe('OIDC identity validation', () => {
	const claims = {sub: 'user-1', nonce: 'nonce', exp: 200, iat: 100};
	const failureMessage = (action: () => void) => {
		try {
			action();
		} catch (err) {
			return (err as {body: {message: string}}).body.message;
		}
		throw new Error('Expected validation to fail');
	};

	it('requires the standard ID token security claims before transformation', () => {
		expect(() => validateIdTokenClaims(claims, 'nonce')).not.toThrow();
		expect(failureMessage(() => validateIdTokenClaims({...claims, exp: undefined}, 'nonce'))).toBe(
			'id_token expiration is required'
		);
		expect(failureMessage(() => validateIdTokenClaims({...claims, iat: undefined}, 'nonce'))).toBe(
			'id_token issued-at time is required'
		);
	});

	it('rejects UserInfo claims for a different subject', () => {
		expect(() => validateUserInfoSubject(claims, {sub: 'user-1'})).not.toThrow();
		expect(failureMessage(() => validateUserInfoSubject(claims, {sub: 'user-2'}))).toBe(
			'UserInfo subject does not match id_token subject'
		);
	});
});
