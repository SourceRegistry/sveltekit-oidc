import { error } from '@sveltejs/kit';
import { randomBytes } from 'node:crypto';
import { sign } from '@sourceregistry/node-jwt/promises';

import type {
	OIDCClientAssertionOptions,
	OIDCClientSecretJwtOptions,
	OIDCPrivateKeyJwtOptions
} from './types.js';
import { base64UrlEncode } from './utils.js';

export async function fetchJson<T>(url: string, init?: RequestInit): Promise<T> {
	const response = await fetch(url, init);
	if (!response.ok) {
		throw error(response.status, {
			message: `OIDC request failed for '${url}' with status ${response.status}`
		});
	}

	return (await response.json()) as T;
}

export function asAuthorizationHeader(clientId: string, clientSecret: string) {
	return `Basic ${Buffer.from(`${clientId}:${clientSecret}`).toString('base64')}`;
}

export async function createClientSecretJwtAssertion(
	options: OIDCClientAssertionOptions & OIDCClientSecretJwtOptions
) {
	if (!options.clientSecret) {
		throw error(500, { message: 'clientSecret is required for client_secret_jwt' });
	}

	const algorithm = options.algorithm ?? 'HS256';
	const now = Math.floor(Date.now() / 1000);

	return sign(
		{
			iss: options.clientId,
			sub: options.clientId,
			aud: options.tokenEndpoint,
			jti: base64UrlEncode(randomBytes(24)),
			iat: now,
			exp: now + (options.expiresInSeconds ?? 60)
		},
		options.clientSecret,
		{ alg: algorithm, typ: 'JWT' }
	);
}

export async function createPrivateKeyJwtAssertion(
	options: OIDCClientAssertionOptions & OIDCPrivateKeyJwtOptions
) {
	const algorithm = options.algorithm ?? 'RS256';
	const now = Math.floor(Date.now() / 1000);

	return sign(
		{
			iss: options.clientId,
			sub: options.clientId,
			aud: options.tokenEndpoint,
			jti: base64UrlEncode(randomBytes(24)),
			iat: now,
			exp: now + (options.expiresInSeconds ?? 60)
		},
		options.privateKey,
		{ alg: algorithm, typ: 'JWT', ...(options.keyId ? { kid: options.keyId } : {}) }
	);
}
