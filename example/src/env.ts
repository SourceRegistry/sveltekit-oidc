import {defineEnvVars} from '@sveltejs/kit/env';

export const variables = defineEnvVars({
    PUBLIC_OIDC_ISSUER: {public: true},
    PUBLIC_OIDC_CLIENT_ID: {public: true},
    SECRET_OIDC_CLIENT_SECRET: {},
    SECRET_OIDC_COOKIE_SECRET: {}
});
