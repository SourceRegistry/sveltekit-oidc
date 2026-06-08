import {oidc} from "$lib/server/configurations/oidc.configuration";
import {redirect} from "@sveltejs/kit";

export const load = async (event) => {
    const session = await oidc.getPublicSession(event);
    if (!session?.isAuthenticated) redirect(302, "/auth/login");

    // `requireAuth` resolves the typed `AppSession` (TSession), inferred from
    // `transformSession` — `permissions` is available with no casts.
    const fullSession = await oidc.requireAuth(event);

    return {session, permissions: fullSession.permissions}
}
