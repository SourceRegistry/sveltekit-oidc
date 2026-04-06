import { error } from '@sveltejs/kit';

import { demoOIDC } from '$lib/demo/server/oidc.js';

export const POST =
	demoOIDC?.backChannelLogoutHandler() ??
	(() => {
		throw error(503, { message: 'Demo OIDC is not configured' });
	});
