# sveltekit-oidc example

This application demonstrates the current v2 API. CI installs the package produced by the parent
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

The example enables insecure HTTP and a non-secure cookie for local development. Production applications should use the HTTPS and secure-cookie defaults.
