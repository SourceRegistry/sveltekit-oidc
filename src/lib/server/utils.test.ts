import {createCipheriv, createHash, randomBytes} from 'node:crypto';
import {describe, expect, it} from 'vitest';

import {
    collectGroups,
    createSignedValue,
    decodeOAuthState,
    encodeOAuthState,
    findAudienceProblem,
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
        const value = serializeSignedCookie({sub: 'user-1', groups: ['admin']}, secret, 'session');

        expect(parseSignedCookie<{sub: string; groups: string[]}>(value, secret, 'session')).toEqual({
            sub: 'user-1',
            groups: ['admin']
        });
    });

    it('does not expose plaintext payload data', () => {
        const value = serializeSignedCookie({refreshToken: 'secret-refresh-token'}, 'test-secret', 'session');

        expect(value).not.toContain('secret-refresh-token');
        expect(value.startsWith('v3.')).toBe(true);
    });

    it('rejects tampered values', () => {
        const secret = 'test-secret';
        const value = serializeSignedCookie({sub: 'user-1'}, secret, 'session');
        const tampered = `${value}x`;

        expect(parseSignedCookie(tampered, secret, 'session')).toBeNull();
    });

    it('binds a value to its purpose', () => {
        const secret = 'test-secret';
        const value = serializeSignedCookie({id: 'session-1'}, secret, 'session-reference');

        expect(parseSignedCookie(value, secret, 'session-reference')).toEqual({id: 'session-1'});
        expect(parseSignedCookie(value, secret, 'session')).toBeNull();
        expect(parseSignedCookie(value, secret, 'state')).toBeNull();
    });

    it('encrypts with the first secret and decrypts with any listed secret', () => {
        const oldValue = serializeSignedCookie({sub: 'user-1'}, 'old-secret', 'session');
        const rotated = ['new-secret', 'old-secret'];
        const newValue = serializeSignedCookie({sub: 'user-2'}, rotated, 'session');

        expect(parseSignedCookie(oldValue, rotated, 'session')).toEqual({sub: 'user-1'});
        expect(parseSignedCookie(newValue, 'new-secret', 'session')).toEqual({sub: 'user-2'});
        expect(parseSignedCookie(newValue, 'old-secret', 'session')).toBeNull();
    });

    it('still reads values written in the previous v2 format', () => {
        const secret = 'test-secret';
        const key = createHash('sha256').update(`sveltekit-oidc-cookie:${secret}`).digest();
        const iv = randomBytes(12);
        const cipher = createCipheriv('aes-256-gcm', key, iv);
        const ciphertext = Buffer.concat([cipher.update(JSON.stringify({sub: 'user-1'}), 'utf8'), cipher.final()]);
        const legacy = `v2.${iv.toString('base64url')}.${cipher.getAuthTag().toString('base64url')}.${ciphertext.toString('base64url')}`;

        expect(parseSignedCookie(legacy, secret, 'session')).toEqual({sub: 'user-1'});
    });

    it('rejects legacy signed-only values', () => {
        const secret = 'test-secret';
        const value = createSignedValue(Buffer.from(JSON.stringify({sub: 'user-1'})).toString('base64url'), secret);

        expect(parseSignedCookie(value, secret, 'session')).toBeNull();
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

    it('carries the callback restart count through the encrypted state', () => {
        const state = encodeOAuthState('token-123', '/admin', secret, 1);

        expect(decodeOAuthState(state, secret)).toEqual({token: 'token-123', returnTo: '/admin', restarts: 1});
        expect(decodeOAuthState(encodeOAuthState('token-123', undefined, secret, 1), secret)).toEqual({
            token: 'token-123',
            restarts: 1
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

    it('never returns a token that cannot be used in a cookie name', () => {
        expect(decodeOAuthState('bad token;', secret)).toEqual({token: null});
        expect(decodeOAuthState('bad token;.signature', secret)).toEqual({token: null});
        expect(decodeOAuthState(encodeOAuthState('bad token;', '/admin', secret), secret)).toEqual({token: null});
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

    it('rejects same-origin paths that normalize to a protocol-relative URL', () => {
        for (const path of ['/.//attacker.example.test', '/..//attacker.example.test', '/a/..//attacker.example.test']) {
            expect(internalRedirectPath(event, path, '/')).toBe('/');
        }
        expect(internalRedirectPath(event, 'https://app.example.test/.//attacker.example.test', '/')).toBe('/');
    });
});

describe('findAudienceProblem', () => {
    it('requires the client and only explicitly trusted extra audiences', () => {
        expect(findAudienceProblem({aud: 'client'}, 'client')).toBeUndefined();
        expect(findAudienceProblem({aud: ['client', 'api']}, 'client', ['api'])).toBeUndefined();
        expect(findAudienceProblem({aud: ['client', 'other']}, 'client')).toBe('audience');
        expect(findAudienceProblem({aud: 'other'}, 'client')).toBe('audience');
        expect(findAudienceProblem({}, 'client')).toBe('audience');
    });

    it('rejects an authorized party other than the client', () => {
        expect(findAudienceProblem({aud: 'client', azp: 'client'}, 'client')).toBeUndefined();
        expect(findAudienceProblem({aud: 'client', azp: 'other'}, 'client')).toBe('authorized_party');
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
import '$app/server';
