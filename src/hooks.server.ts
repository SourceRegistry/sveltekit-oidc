import type { Handle } from '@sveltejs/kit';

import { demoOIDC } from './lib/demo/server/oidc.js';

export const handle: Handle = async ({ event, resolve }) => {
	if (!demoOIDC) {
		return resolve(event);
	}

	return demoOIDC?.handle({ event, resolve }) ?? resolve(event);
};
