# sveltekit-oidc example

This application demonstrates the current API with SvelteKit 3. CI installs the package produced by the parent
checkout before checking and building the application, so it also serves as a package-consumer test.

Configure at least:

```env
PUBLIC_OIDC_ISSUER=http://localhost:8080/realms/example
PUBLIC_OIDC_CLIENT_ID=sveltekit-example
SECRET_OIDC_CLIENT_SECRET=replace-me
SECRET_OIDC_COOKIE_SECRET=replace-with-at-least-32-random-bytes
```

Generate a cookie secret and start the application:

```sh
npm run generate:cookieSecret
npm install
npm run dev
```

Replace `SECRET_OIDC_COOKIE_SECRET` with the generated value. Configure the provider client for
Authorization Code flow and allow `http://localhost:5173/auth/callback` as a redirect URI. If using
provider logout, allow `http://localhost:5173/` as a post-logout redirect URI. The example uses
in-memory session and back-channel logout stores. They are suitable for a single local process;
use shared stores in a multi-instance deployment. If your provider supports back-channel logout,
register `http://localhost:5173/auth/backchannel-logout` with it.

The example enables insecure HTTP and a non-secure cookie for local development. Production applications should use the HTTPS and secure-cookie defaults.
