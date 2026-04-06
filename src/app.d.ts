import type { OIDCHandleLocals } from '$lib/server';

// See https://svelte.dev/docs/kit/types#app.d.ts
// for information about these interfaces
declare global {
	namespace App {
		// interface Error {}
		interface Locals {
			oidc?: OIDCHandleLocals;
		}
		// interface PageData {}
		// interface PageState {}
		// interface Platform {}
	}
}

export {};
