import {getContext, hasContext, setContext} from 'svelte';

import type {OIDCDiscoveryDocument, OIDCHandleLocals, OIDCPublicSession, OIDCUserClaims} from '../server/index.js';

type LocalsIdentity = App.Locals extends {
	oidc?: OIDCHandleLocals<infer I, any>;
}
	? I
	: OIDCUserClaims;

export type OIDCClientContextValue<TIdentity extends OIDCUserClaims = OIDCUserClaims> = {
	isAuthenticated: boolean;
	session: OIDCPublicSession<TIdentity> | null;
	identity: OIDCPublicSession<TIdentity>['identity'] | undefined;
	groups: OIDCPublicSession<TIdentity>['groups'];
	issuer: string;
	metadata?: Pick<
		OIDCDiscoveryDocument,
		| 'issuer'
		| 'check_session_iframe'
		| 'end_session_endpoint'
		| 'backchannel_logout_supported'
		| 'backchannel_logout_session_supported'
	>;
	status: 'authenticated' | 'unauthenticated' | 'expired' | 'revoked';
	revalidating: boolean;
	login: (returnTo?: string) => void;
	logout: (clearSessionOnly?: boolean) => Promise<void>;
	revalidate: () => Promise<void>;
};

const OIDC_CONTEXT_KEY = Symbol('sveltekit-oidc-context');

export function setOIDCContext<TIdentity extends OIDCUserClaims = OIDCUserClaims>(
	value: OIDCClientContextValue<TIdentity>
): OIDCClientContextValue<TIdentity> {
	setContext(OIDC_CONTEXT_KEY, value);
	return value;
}

export function getOIDCContext<TIdentity extends OIDCUserClaims = LocalsIdentity>(): OIDCClientContextValue<TIdentity> {
	return getContext<OIDCClientContextValue<TIdentity>>(OIDC_CONTEXT_KEY);
}

export function useOIDC<TIdentity extends OIDCUserClaims = LocalsIdentity>(): OIDCClientContextValue<TIdentity> {
	if (!hasContext(OIDC_CONTEXT_KEY)) {
		throw new Error('OIDC context is not available. Wrap this component tree with <OIDCContext>.');
	}

	return getOIDCContext<TIdentity>();
}
