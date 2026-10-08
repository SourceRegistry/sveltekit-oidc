import type { Handle } from '@sveltejs/kit/hooks';
import {oidc} from "#lib/server/configurations/oidc.configuration.js";

export const handle: Handle = oidc.handle
