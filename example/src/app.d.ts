import type { OIDCLocals } from '@sourceregistry/sveltekit-oidc/server';
import type { oidc } from '$lib/server/configurations/oidc.configuration';

// See https://svelte.dev/docs/kit/types#app.d.ts
declare global {
	namespace App {
		// interface Error {}
		interface Locals {
			oidc?: OIDCLocals<typeof oidc>;
		}
		// interface PageData {}
		// interface PageState {}
		// interface Platform {}
	}
}

export {};
