import {redirect} from '@sveltejs/kit';

import {oidc} from '$lib/server/configurations/oidc.configuration';

export const load = async (event) => {
    const session = await oidc.getPublicSession(event);
    if (!session?.isAuthenticated) redirect(302, '/auth/login');

    return {session};
};
