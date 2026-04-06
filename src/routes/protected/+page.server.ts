import { redirect } from '@sveltejs/kit';

import { demoOIDC } from '$lib/demo/server/oidc.js';

export async function load(event) {
	if (!demoOIDC) {
		return {
			enabled: false,
			session: null
		};
	}

	const session = await demoOIDC.getPublicSession(event);
	if (!session?.isAuthenticated) {
		throw redirect(302, `/auth/login?returnTo=${encodeURIComponent('/protected')}`);
	}

	return {
		enabled: true,
		session
	};
}
