import { error } from '@sveltejs/kit';

import { demoOIDC } from '$lib/demo/server/oidc.js';

const handler =
	demoOIDC?.logoutHandler() ??
	(() => {
		throw error(503, { message: 'Demo OIDC is not configured' });
	});

export const GET = handler;
export const POST = handler;
