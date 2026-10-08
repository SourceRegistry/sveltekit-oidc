import {createOIDC} from '@sourceregistry/sveltekit-oidc/server';
import {PUBLIC_OIDC_ISSUER, PUBLIC_OIDC_CLIENT_ID} from '$app/env/public';
import {SECRET_OIDC_CLIENT_SECRET, SECRET_OIDC_COOKIE_SECRET} from '$app/env/private';

type AppIdentity = {
    sub: string;
    email?: string;
    name?: string;
    roles: string[];
};

export const oidc = createOIDC<AppIdentity>({
    issuer: PUBLIC_OIDC_ISSUER,
    clientId: PUBLIC_OIDC_CLIENT_ID,
    clientSecret: SECRET_OIDC_CLIENT_SECRET,
    cookieSecret: SECRET_OIDC_COOKIE_SECRET,
    clockSkewSeconds: 30,
    sessionStore: 'memory',
    allowInsecureHttp: true, // Local development only; omit this in production.
    cookieOptions: {
        secure: false
    },
    resolveIdentity: ({idTokenClaims, userInfo}) => ({
        sub: idTokenClaims.sub,
        email: (userInfo?.email ?? idTokenClaims.email) as string | undefined,
        name: (userInfo?.name ?? idTokenClaims.name) as string | undefined,
        roles: ((userInfo?.roles ?? idTokenClaims.roles) as string[] | undefined) ?? []
    })
});
