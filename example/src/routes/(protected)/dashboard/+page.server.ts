import {oidc} from "$lib/server/configurations/oidc.configuration";
import {redirect} from "@sveltejs/kit";

export const load = async (event) => {
    const session = await oidc.getPublicSession(event);
    if (!session?.isAuthenticated) redirect(302, "/auth/login");
    return {session}
}
