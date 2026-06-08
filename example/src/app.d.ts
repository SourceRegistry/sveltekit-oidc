import type { OIDCHandleLocals } from '@sourceregistry/sveltekit-oidc/server';
import type { AppClaims } from '$lib/server/configurations/oidc.configuration';

// See https://svelte.dev/docs/kit/types#app.d.ts
// for information about these interfaces
declare global {
	namespace App {
		// interface Error {}
		interface Locals {
			oidc?: OIDCHandleLocals<AppClaims>;
		}
		// interface PageData {}
		// interface PageState {}
		// interface Platform {}
	}
}

export {};
