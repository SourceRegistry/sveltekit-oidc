import { OpenIDConnect } from "@sourceregistry/sveltekit-oidc/server";
import {env as $public} from "$env/dynamic/public";
import {env as $private} from "$env/dynamic/private";

export const oidc = OpenIDConnect({
    issuer: $public['PUBLIC_OIDC_ISSUER']!,
    clientId: $public['PUBLIC_OIDC_CLIENT_ID']!,
    clientSecret: $private['SECRET_OIDC_CLIENT_SECRET']!,
    cookieSecret: $private['SECRET_OIDC_COOKIE_SECRET']!,
    clockSkewSeconds: 30,
    sessionStore: 'memory',
    cookieOptions: {
        secure: false,
    },
    // Project provider-specific claims into a typed shape. TClaims is inferred
    // from this return type and threaded through the session, locals, and client context.
    transformClaims: (claims) => ({
        ...claims,
        roles: (claims.roles as string[] | undefined) ?? [],
    }),
    // Project the session into a typed shape with app-specific data.
    // TSession is inferred from this return type and threaded through the
    // session store, locals, and requireAuth/handleCallback results.
    transformSession: (session) => ({
        ...session,
        permissions: session.user?.roles ?? [],
    }),
});
