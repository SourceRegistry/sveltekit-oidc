import { getContext, hasContext, setContext } from 'svelte';

import type { OIDCDiscoveryDocument, OIDCPublicSession, OIDCUserClaims } from '../server/index.js';

export type OIDCClientContextValue<TClaims extends OIDCUserClaims = OIDCUserClaims> = {
	isAuthenticated: boolean;
	session: OIDCPublicSession<TClaims> | null;
	user: OIDCPublicSession<TClaims>['user'];
	claims: OIDCPublicSession<TClaims>['claims'];
	groups: OIDCPublicSession<TClaims>['groups'];
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

export function setOIDCContext<TClaims extends OIDCUserClaims = OIDCUserClaims>(
	value: OIDCClientContextValue<TClaims>
): OIDCClientContextValue<TClaims> {
	setContext(OIDC_CONTEXT_KEY, value);
	return value;
}

export function getOIDCContext<TClaims extends OIDCUserClaims = OIDCUserClaims>(): OIDCClientContextValue<TClaims> {
	return getContext<OIDCClientContextValue<TClaims>>(OIDC_CONTEXT_KEY);
}

export function useOIDC<TClaims extends OIDCUserClaims = OIDCUserClaims>(): OIDCClientContextValue<TClaims> {
	if (!hasContext(OIDC_CONTEXT_KEY)) {
		throw new Error('OIDC context is not available. Wrap this component tree with <OIDCContext>.');
	}

	return getOIDCContext<TClaims>();
}
