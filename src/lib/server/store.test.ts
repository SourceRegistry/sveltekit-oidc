import {describe, expect, it} from 'vitest';

import {createInMemoryBackChannelLogoutStore, createInMemorySessionStore} from './store.js';

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
                idTokenClaims: {sub: 'user-1'},
                identity: {sub: 'user-1'},
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
                idTokenClaims: {sub: 'user-1'},
                identity: {sub: 'user-1'},
                tokens: {
                    accessToken: 'access',
                    tokenType: 'Bearer',
                    scope: ['openid']
                },
                createdAt: 0,
                refreshedAt: 0
            })
        ).resolves.toBe(true);

        await expect(
            store.isRevoked({
                issuer: 'https://issuer.example',
                clientId: 'client',
                sub: 'user-1',
                groups: [],
                idTokenClaims: {sub: 'user-1'},
                identity: {sub: 'user-1'},
                tokens: {
                    accessToken: 'access',
                    tokenType: 'Bearer',
                    scope: ['openid']
                },
                createdAt: 2,
                refreshedAt: 2
            })
        ).resolves.toBe(false);
    });

    it('limits a logout token with both sid and sub to the identified session', async () => {
        const store = createInMemoryBackChannelLogoutStore();
        const session = (sid: string) => ({
            issuer: 'https://issuer.example',
            clientId: 'client',
            sid,
            sub: 'user-1',
            groups: [],
            idTokenClaims: {sub: 'user-1'},
            identity: {sub: 'user-1'},
            tokens: {accessToken: 'access', tokenType: 'Bearer', scope: ['openid']},
            createdAt: 100,
            refreshedAt: 100
        });

        await store.revoke({
            issuer: 'https://issuer.example',
            clientId: 'client',
            sid: 'sid-1',
            sub: 'user-1',
            jti: 'jti-1',
            iat: 101
        });

        await expect(store.isRevoked(session('sid-1'))).resolves.toBe(true);
        await expect(store.isRevoked(session('sid-2'))).resolves.toBe(false);
    });
});

describe('createInMemorySessionStore', () => {
    it('roundtrips sessions by id', async () => {
        const store = createInMemorySessionStore();
        const session = {
            issuer: 'https://issuer.example',
            clientId: 'client',
            sub: 'user-1',
            groups: ['admin'],
            idTokenClaims: {sub: 'user-1'},
            identity: {sub: 'user-1'},
            tokens: {
                accessToken: 'access',
                tokenType: 'Bearer',
                scope: ['openid']
            },
            createdAt: Math.floor(Date.now() / 1000),
            refreshedAt: Math.floor(Date.now() / 1000)
        };

        await store.set('session-1', session);
        await expect(store.get('session-1')).resolves.toEqual(session);

        await store.delete('session-1');
        await expect(store.get('session-1')).resolves.toBeNull();
    });

    const sessionCreatedAt = (createdAt: number) => ({
        issuer: 'https://issuer.example',
        clientId: 'client',
        sub: 'user-1',
        groups: [],
        idTokenClaims: {sub: 'user-1'},
        identity: {sub: 'user-1'},
        tokens: {accessToken: 'access', tokenType: 'Bearer', scope: ['openid']},
        createdAt,
        refreshedAt: createdAt
    });

    it('drops sessions older than maxAgeSeconds', async () => {
        const store = createInMemorySessionStore({maxAgeSeconds: 60});
        const now = Math.floor(Date.now() / 1000);

        await store.set('expired', sessionCreatedAt(now - 61));
        await store.set('current', sessionCreatedAt(now));

        await expect(store.get('expired')).resolves.toBeNull();
        await expect(store.get('current')).resolves.toMatchObject({createdAt: now});
    });

    it('evicts the least recently written session beyond maxEntries', async () => {
        const store = createInMemorySessionStore({maxEntries: 2});
        const now = Math.floor(Date.now() / 1000);

        await store.set('evict-a', sessionCreatedAt(now));
        await store.set('evict-b', sessionCreatedAt(now));
        await store.set('evict-a', sessionCreatedAt(now));
        await store.set('evict-c', sessionCreatedAt(now));

        await expect(store.get('evict-b')).resolves.toBeNull();
        await expect(store.get('evict-a')).resolves.not.toBeNull();
        await expect(store.get('evict-c')).resolves.not.toBeNull();
    });

    it('rejects invalid limits', () => {
        expect(() => createInMemorySessionStore({maxAgeSeconds: 0})).toThrow(TypeError);
        expect(() => createInMemorySessionStore({maxEntries: 1.5})).toThrow(TypeError);
    });
});
import '$app/server';
