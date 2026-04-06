import {createInMemorySessionStore, OpenIDConnect} from "@sourceregistry/sveltekit-oidc/server";
import {env as $public} from "$env/dynamic/public";
import {env as $private} from "$env/dynamic/private";

export const oidc = OpenIDConnect({
    issuer: $public['PUBLIC_OIDC_ISSUER']!,
    clientId: $public['PUBLIC_OIDC_CLIENT_ID']!,
    clientSecret: $private['SECRET_OIDC_CLIENT_SECRET']!,
    cookieSecret: $private['SECRET_OIDC_COOKIE_SECRET']!,
    clockSkewSeconds: 30,
    cookieOptions: {
        secure: false,
    },
    sessionStore: createInMemorySessionStore(),
})
