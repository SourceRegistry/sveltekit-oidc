import { error } from '@sveltejs/kit';
import {
	createCipheriv,
	createDecipheriv,
	createHash,
	createHmac,
	randomBytes,
	timingSafeEqual
} from 'node:crypto';

import type { CookieOptions, OIDCPublicSession, OIDCSession, OIDCUserClaims } from './types.js';

export function base64UrlEncode(value: string | Uint8Array): string {
	const buffer = typeof value === 'string' ? Buffer.from(value, 'utf8') : Buffer.from(value);
	return buffer.toString('base64url');
}

export function createPKCEPair(length = 64) {
	const verifier = base64UrlEncode(randomBytes(length)).slice(0, length);
	const challenge = createHash('sha256').update(verifier).digest('base64url');

	return { verifier, challenge };
}

export function normalizeIssuer(issuer: string) {
	return issuer.endsWith('/') ? issuer.slice(0, -1) : issuer;
}

export function normalizeScope(scope?: string | string[]) {
	if (!scope) return ['openid', 'profile', 'email'];
	const arr = typeof scope === 'string' ? scope.trim().split(/\s+/) : scope;
	return arr.length ? [...new Set(arr)] : ['openid', 'profile', 'email'];
}

export function normalizeStringArray(value: unknown): string[] {
	if (!value) return [];
	if (Array.isArray(value)) {
		return value.filter((item): item is string => typeof item === 'string');
	}
	if (typeof value === 'string') {
		return value.trim() ? [value] : [];
	}

	return [];
}

export function collectGroups<TClaims extends OIDCUserClaims = OIDCUserClaims>(
	...sources: Array<TClaims | undefined>
) {
	return [
		...new Set(
			sources.flatMap((source) =>
				normalizeStringArray(source?.groups).concat(normalizeStringArray(source?.roles))
			)
		)
	];
}

export function createSignedValue(value: string, secret: string) {
	const mac = createHmac('sha256', secret).update(value).digest('base64url');
	return `${value}.${mac}`;
}

export function verifySignedValue(value: string, secret: string) {
	const lastDot = value.lastIndexOf('.');
	if (lastDot === -1) return null;

	const payload = value.slice(0, lastDot);
	const signature = value.slice(lastDot + 1);
	const expected = createHmac('sha256', secret).update(payload).digest();
	const actual = Buffer.from(signature, 'base64url');

	if (expected.length !== actual.length || !timingSafeEqual(expected, actual)) {
		return null;
	}

	return payload;
}

function cookieEncryptionKey(secret: string) {
	return createHash('sha256').update(`sveltekit-oidc-cookie:${secret}`).digest();
}

export function serializeSignedCookie(payload: unknown, secret: string) {
	const iv = randomBytes(12);
	const cipher = createCipheriv('aes-256-gcm', cookieEncryptionKey(secret), iv);
	const ciphertext = Buffer.concat([
		cipher.update(JSON.stringify(payload), 'utf8'),
		cipher.final()
	]);
	const tag = cipher.getAuthTag();

	return `v2.${iv.toString('base64url')}.${tag.toString('base64url')}.${ciphertext.toString('base64url')}`;
}

export function parseSignedCookie<T>(value: string | undefined, secret: string): T | null {
	if (!value) return null;

	const parts = value.split('.');
	if (parts.length !== 4 || parts[0] !== 'v2') return null;

	try {
		const [, iv, tag, ciphertext] = parts;
		const decipher = createDecipheriv('aes-256-gcm', cookieEncryptionKey(secret), Buffer.from(iv, 'base64url'));
		decipher.setAuthTag(Buffer.from(tag, 'base64url'));
		const plaintext = Buffer.concat([
			decipher.update(Buffer.from(ciphertext, 'base64url')),
			decipher.final()
		]);

		return JSON.parse(plaintext.toString('utf8')) as T;
	} catch {
		return null;
	}
}

export function buildCookieOptions(options?: Partial<CookieOptions>): CookieOptions {
	return {
		httpOnly: true,
		path: '/',
		sameSite: 'lax',
		secure: true,
		...options
	};
}

export function parseProviderError(event: { url: URL }) {
	const code = event.url.searchParams.get('error');
	if (!code) return null;

	return error(400, {
		message: event.url.searchParams.get('error_description') ?? code
	});
}

export function absoluteUrl(event: {url: URL}, pathOrUrl: string) {
	if (/^https?:\/\//i.test(pathOrUrl)) return pathOrUrl;
	return new URL(pathOrUrl, event.url).toString();
}

export function internalRedirectPath(event: {url: URL}, pathOrUrl: string | undefined, fallback = '/') {
	if (!pathOrUrl) return fallback;

	try {
		const url = new URL(pathOrUrl, event.url);
		if (url.origin !== event.url.origin) return fallback;

		return `${url.pathname}${url.search}${url.hash}`;
	} catch {
		return fallback;
	}
}

export function toPublicSession<TClaims extends OIDCUserClaims = OIDCUserClaims>(
	session: OIDCSession<TClaims> | null
): OIDCPublicSession<TClaims> | null {
	if (!session) return null;

	return {
		isAuthenticated: true,
		user: session.user,
		claims: session.claims,
		groups: session.groups,
		scope: session.tokens.scope,
		expiresAt: session.tokens.expiresAt,
		issuer: session.issuer,
		sessionState: session.sessionState,
		sid: session.sid,
		sub: session.sub
	};
}
