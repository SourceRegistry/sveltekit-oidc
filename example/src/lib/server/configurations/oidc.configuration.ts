import {createInMemorySessionStore, OpenIDConnect, type OIDCInferClaims} from "@sourceregistry/sveltekit-oidc/server";
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
    // Project provider-specific claims into a typed shape. `TClaims` is inferred
    // from this return type and threaded through the session, locals, and client context.
    transformClaims: (claims) => ({
        ...claims,
        roles: (claims.roles as string[] | undefined) ?? [],
    }),
})

// Extract the inferred custom claims type so it can be applied to `App.Locals`
// (see src/app.d.ts) and to `<OIDCContext<AppClaims>>` on the client.
export type AppClaims = OIDCInferClaims<typeof oidc>;
