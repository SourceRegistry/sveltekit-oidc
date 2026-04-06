import { error, type RequestEvent } from '@sveltejs/kit';
import { createHash, createHmac, randomBytes, timingSafeEqual } from 'node:crypto';

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

export function normalizeScope(scope?: string[]) {
	return scope?.length ? [...new Set(scope)] : ['openid', 'profile', 'email'];
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

export function collectGroups(...sources: Array<OIDCUserClaims | undefined>) {
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

export function serializeSignedCookie(payload: unknown, secret: string) {
	return createSignedValue(base64UrlEncode(JSON.stringify(payload)), secret);
}

export function parseSignedCookie<T>(value: string | undefined, secret: string): T | null {
	if (!value) return null;

	const payload = verifySignedValue(value, secret);
	if (!payload) return null;

	try {
		return JSON.parse(Buffer.from(payload, 'base64url').toString('utf8')) as T;
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

export function parseProviderError(event: RequestEvent) {
	const code = event.url.searchParams.get('error');
	if (!code) return null;

	return error(400, {
		message: event.url.searchParams.get('error_description') ?? code
	});
}

export function absoluteUrl(event: RequestEvent, pathOrUrl: string) {
	if (/^https?:\/\//i.test(pathOrUrl)) return pathOrUrl;
	return new URL(pathOrUrl, event.url).toString();
}

export function toPublicSession(session: OIDCSession | null): OIDCPublicSession | null {
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
