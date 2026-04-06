import {oidc} from "$lib/server/configurations/oidc.configuration";

export const load = async (event) => {
    return {
        session: await oidc.getPublicSession(event),
        config: await oidc.getSessionManagementConfig()
    }
}
