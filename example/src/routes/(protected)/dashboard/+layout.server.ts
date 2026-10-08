import {oidc} from "#lib/server/configurations/oidc.configuration.js";

export const load = async (event) => {
    return {
        session: await oidc.getPublicSession(event),
        config: await oidc.getSessionManagementConfig()
    }
}
