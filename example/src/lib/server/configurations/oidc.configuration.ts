import {createOIDC} from '@sourceregistry/sveltekit-oidc/server';
import {env as $public} from '$env/dynamic/public';
import {env as $private} from '$env/dynamic/private';

type AppIdentity = {
    sub: string;
    email?: string;
    name?: string;
    roles: string[];
};

export const oidc = createOIDC<AppIdentity>({
    issuer: $public['PUBLIC_OIDC_ISSUER']!,
    clientId: $public['PUBLIC_OIDC_CLIENT_ID']!,
    clientSecret: $private['SECRET_OIDC_CLIENT_SECRET']!,
    cookieSecret: $private['SECRET_OIDC_COOKIE_SECRET']!,
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
