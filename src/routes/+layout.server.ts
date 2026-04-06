import { demoOIDC } from '$lib/demo/server/oidc.js';

export async function load(event) {
	if (!demoOIDC) {
		return {
			demoOIDCConfigured: false,
			session: null,
			sessionManagement: null
		};
	}

	return {
		demoOIDCConfigured: true,
		session: await demoOIDC.getPublicSession(event),
		sessionManagement: await demoOIDC.getSessionManagementConfig()
	};
}
