import { getContext, hasContext, setContext } from 'svelte';

import type { OIDCDiscoveryDocument, OIDCPublicSession } from '../server/index.js';

export type OIDCClientContextValue = {
	isAuthenticated: boolean;
	session: OIDCPublicSession | null;
	user: OIDCPublicSession['user'];
	claims: OIDCPublicSession['claims'];
	groups: OIDCPublicSession['groups'];
	metadata?: Pick<
		OIDCDiscoveryDocument,
		| 'issuer'
		| 'check_session_iframe'
		| 'end_session_endpoint'
		| 'backchannel_logout_supported'
		| 'backchannel_logout_session_supported'
	>;
	status: 'authenticated' | 'unauthenticated' | 'expired' | 'revoked';
	login: (returnTo?: string) => void;
	logout: (clearSessionOnly?: boolean) => Promise<void>;
	revalidate: () => Promise<void>;
};

const OIDC_CONTEXT_KEY = Symbol('sveltekit-oidc-context');

export function setOIDCContext(value: OIDCClientContextValue): OIDCClientContextValue {
	setContext(OIDC_CONTEXT_KEY, value);
	return value;
}

export function getOIDCContext(): OIDCClientContextValue {
	return getContext<OIDCClientContextValue>(OIDC_CONTEXT_KEY);
}

export function useOIDC(): OIDCClientContextValue {
	if (!hasContext(OIDC_CONTEXT_KEY)) {
		throw new Error('OIDC context is not available. Wrap this component tree with <OIDCContext>.');
	}

	return getOIDCContext();
}
