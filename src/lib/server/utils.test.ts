import {describe, expect, it} from 'vitest';

import {
    collectGroups,
    createSignedValue,
    decodeOAuthState,
    encodeOAuthState,
    internalRedirectPath,
    normalizeScope,
    parseSignedCookie,
    serializeSignedCookie,
    validateIdTokenClaims,
    validateRefreshedIdTokenClaims,
    validateUserInfoSubject
} from './utils.js';

describe('normalizeScope', () => {
    it('returns defaults when no scope is provided', () => {
        expect(normalizeScope()).toEqual(['openid', 'profile', 'email']);
    });

    it('deduplicates scope values while preserving order', () => {
        expect(normalizeScope(['openid', 'email', 'openid', 'profile'])).toEqual(['openid', 'email', 'profile']);
    });

    it('always includes the required openid scope', () => {
        expect(normalizeScope(['profile', 'email'])).toEqual(['openid', 'profile', 'email']);
    });
});

describe('collectGroups', () => {
    it('merges groups and roles across sources', () => {
        expect(
            collectGroups({sub: 'a', groups: ['admin', 'team-a']}, {
                sub: 'a',
                roles: ['team-a', 'editor']
            } as never)
        ).toEqual(['admin', 'team-a', 'editor']);
    });
});

describe('signed cookie helpers', () => {
    it('roundtrips payloads', () => {
        const secret = 'test-secret';
        const value = serializeSignedCookie({sub: 'user-1', groups: ['admin']}, secret);

        expect(parseSignedCookie<{sub: string; groups: string[]}>(value, secret)).toEqual({
            sub: 'user-1',
            groups: ['admin']
        });
    });

    it('does not expose plaintext payload data', () => {
        const value = serializeSignedCookie({refreshToken: 'secret-refresh-token'}, 'test-secret');

        expect(value).not.toContain('secret-refresh-token');
        expect(value.startsWith('v2.')).toBe(true);
    });

    it('rejects tampered values', () => {
        const secret = 'test-secret';
        const value = serializeSignedCookie({sub: 'user-1'}, secret);
        const tampered = `${value}x`;

        expect(parseSignedCookie(tampered, secret)).toBeNull();
    });

    it('rejects legacy signed-only values', () => {
        const secret = 'test-secret';
        const value = createSignedValue(Buffer.from(JSON.stringify({sub: 'user-1'})).toString('base64url'), secret);

        expect(parseSignedCookie(value, secret)).toBeNull();
    });
});

describe('encodeOAuthState / decodeOAuthState', () => {
    const secret = 'test-cookie-secret';

    it('returns the bare token unchanged when there is no returnTo', () => {
        expect(encodeOAuthState('token-123', undefined, secret)).toBe('token-123');
    });

    it('roundtrips a token and returnTo through the wire format', () => {
        const state = encodeOAuthState('token-123', '/admin/clients?tab=disabled', secret);

        expect(state).not.toBe('token-123');
        expect(decodeOAuthState(state, secret)).toEqual({
            token: 'token-123',
            returnTo: '/admin/clients?tab=disabled'
        });
    });

    it('still recovers the token from a bare, pre-upgrade-format state (no embedded returnTo)', () => {
        // A login started right before a version bump that adds this
        // encoding sends a bare random token as `state` - the callback must
        // still recognize it after the upgrade.
        expect(decodeOAuthState('token-123', secret)).toEqual({
            token: 'token-123'
        });
    });

    it('rejects a tampered encrypted state', () => {
        const state = encodeOAuthState('token-123', '/admin/clients', secret);
        const tampered = `${state}x`;

        expect(decodeOAuthState(tampered, secret)).toEqual({token: null});
    });

    it('does not decrypt state created with a different secret', () => {
        const state = encodeOAuthState('token-123', '/admin/clients', 'a-different-secret');

        expect(decodeOAuthState(state, secret)).toEqual({token: null});
    });

    it('returns a null token for a missing state value', () => {
        expect(decodeOAuthState(null, secret)).toEqual({token: null});
        expect(decodeOAuthState(undefined, secret)).toEqual({token: null});
    });
});

describe('internalRedirectPath', () => {
    const event = {
        url: new URL('https://app.example.test/current?x=1')
    } as never;

    it('keeps same-origin paths relative', () => {
        expect(internalRedirectPath(event, '/account?tab=settings#profile')).toBe('/account?tab=settings#profile');
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

    it('rejects untrusted audiences and an unexpected authorized party', () => {
        expect(() =>
            validateIdTokenClaims({...claims, aud: ['client', 'api']}, 'nonce', 'client', ['api'])
        ).not.toThrow();
        expect(
            failureMessage(() => validateIdTokenClaims({...claims, aud: ['client', 'attacker']}, 'nonce', 'client'))
        ).toBe('id_token contains an untrusted audience');
        expect(
            failureMessage(() => validateIdTokenClaims({...claims, aud: 'client', azp: 'other'}, 'nonce', 'client'))
        ).toBe('Invalid id_token authorized party');
    });

    it('accepts a nonce-less refresh only when identity claims remain stable', () => {
        const previous = {...claims, aud: 'client', azp: 'client', auth_time: 50};
        const refreshed = {...previous, nonce: undefined, iat: 150, exp: 250};
        expect(() => validateRefreshedIdTokenClaims(previous, refreshed)).not.toThrow();
        expect(
            failureMessage(() =>
                validateRefreshedIdTokenClaims(previous, {
                    ...refreshed,
                    sub: 'user-2'
                })
            )
        ).toBe('Refreshed id_token subject changed');
        expect(
            failureMessage(() =>
                validateRefreshedIdTokenClaims(previous, {
                    ...refreshed,
                    aud: 'other'
                })
            )
        ).toBe('Refreshed id_token audience changed');
    });

    it('rejects UserInfo claims for a different subject', () => {
        expect(() => validateUserInfoSubject(claims, {sub: 'user-1'})).not.toThrow();
        expect(failureMessage(() => validateUserInfoSubject(claims, {sub: 'user-2'}))).toBe(
            'UserInfo subject does not match id_token subject'
        );
    });
});
