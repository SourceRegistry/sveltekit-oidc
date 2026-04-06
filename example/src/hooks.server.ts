import type { Handle } from '@sveltejs/kit';
import {oidc} from "$lib/server/configurations/oidc.configuration";

export const handle: Handle = oidc.handle
