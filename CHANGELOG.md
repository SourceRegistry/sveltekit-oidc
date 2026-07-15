# [2.0.0](https://github.com/SourceRegistry/sveltekit-oidc/compare/v1.8.0...v2.0.0) (2026-07-15)


* feat!: redesign identity and session lifecycle API ([f66e387](https://github.com/SourceRegistry/sveltekit-oidc/commit/f66e387a21c524b8645dabfdf3e0605efa30b68e))


### Features

* add configurable public session projection ([ec9f080](https://github.com/SourceRegistry/sveltekit-oidc/commit/ec9f0807c3662c0d19662152cba4cc213c2d385c))


### BREAKING CHANGES

* replace transformClaims, transformUser, transformSession, and enrichSession with resolveIdentity, beforeSessionPersist, and loadRequestData; expose identity and request data separately.

# [1.8.0](https://github.com/SourceRegistry/sveltekit-oidc/compare/v1.7.0...v1.8.0) (2026-07-15)


### Features

* expose public session projection ([8616a91](https://github.com/SourceRegistry/sveltekit-oidc/commit/8616a91ce807cfe2e8ce96b44a7914b0dcd516e6))

# [1.7.0](https://github.com/SourceRegistry/sveltekit-oidc/compare/v1.6.14...v1.7.0) (2026-07-15)


### Features

* add enrichSession hook for per-request session enrichment ([28af6b2](https://github.com/SourceRegistry/sveltekit-oidc/commit/28af6b282e1a0637a18d42221c4881046a0ad399))

## [1.6.14](https://github.com/SourceRegistry/sveltekit-oidc/compare/v1.6.13...v1.6.14) (2026-07-13)


### Bug Fixes

* session invalidation to not flicker the package + enriched oidc context. ([e3f5e73](https://github.com/SourceRegistry/sveltekit-oidc/commit/e3f5e736d603d530210ba7c78081b152a082e683))

## [1.6.13](https://github.com/SourceRegistry/sveltekit-oidc/compare/v1.6.12...v1.6.13) (2026-07-13)


### Bug Fixes

* stripped typings to bare minimum for requestHandlers when integrating with libraries ([de23575](https://github.com/SourceRegistry/sveltekit-oidc/commit/de23575c318068f711b6ce2643f87f8707b3b30a))

## [1.6.12](https://github.com/SourceRegistry/sveltekit-oidc/compare/v1.6.11...v1.6.12) (2026-07-13)


### Bug Fixes

* stripped typings to bare minimum for requestHandlers when integrating with libraries ([824de32](https://github.com/SourceRegistry/sveltekit-oidc/commit/824de3250f7ece50e659cf2699ba49ff969d68c7))

## [1.6.11](https://github.com/SourceRegistry/sveltekit-oidc/compare/v1.6.10...v1.6.11) (2026-07-12)


### Bug Fixes

* logout bug ([8918ae5](https://github.com/SourceRegistry/sveltekit-oidc/commit/8918ae5ba3d6cde3d0b2546050b9cc9a82523fa5))

## [1.6.10](https://github.com/SourceRegistry/sveltekit-oidc/compare/v1.6.9...v1.6.10) (2026-07-12)


### Bug Fixes

* harden OIDC session validation ([4d27f01](https://github.com/SourceRegistry/sveltekit-oidc/commit/4d27f013d39cb77163f7608a58ef9a3b029f74a4))

## [1.6.9](https://github.com/SourceRegistry/sveltekit-oidc/compare/v1.6.8...v1.6.9) (2026-06-28)


### Bug Fixes

* **oidc:** prevent session flicker on background revalidation ([847fd6f](https://github.com/SourceRegistry/sveltekit-oidc/commit/847fd6f8c96021d9794c4bce1d02e73cfad6ed2c))

## [1.6.8](https://github.com/SourceRegistry/sveltekit-oidc/compare/v1.6.7...v1.6.8) (2026-06-28)


### Bug Fixes

* **hook:** hook didn't set App.Locals['oidc'] now it does ([e83caf2](https://github.com/SourceRegistry/sveltekit-oidc/commit/e83caf28b9640b6b25a8bb3c9807151c419737f7))

## [1.6.7](https://github.com/SourceRegistry/sveltekit-oidc/compare/v1.6.6...v1.6.7) (2026-06-28)


### Bug Fixes

* **hook:** hook didn't set App.Locals['oidc'] now it does ([a797cb4](https://github.com/SourceRegistry/sveltekit-oidc/commit/a797cb4562c686ae7af9d24a0b3d88aa55cd6690))

## [1.6.6](https://github.com/SourceRegistry/sveltekit-oidc/compare/v1.6.5...v1.6.6) (2026-06-27)


### Bug Fixes

* **type:** loosen typings on RequestEvent to allow libraries to use and pass only the required types ([a35b365](https://github.com/SourceRegistry/sveltekit-oidc/commit/a35b365bac530e6ad4e2462587a6254a6a2da476))

## [1.6.5](https://github.com/SourceRegistry/sveltekit-oidc/compare/v1.6.4...v1.6.5) (2026-06-27)


### Bug Fixes

* **type:** loosen typings on RequestEvent to allow libraries to use and pass only the required types ([91d1039](https://github.com/SourceRegistry/sveltekit-oidc/commit/91d1039aaa0d07f73a8e06f5836849d8be8ba383))

## [1.6.4](https://github.com/SourceRegistry/sveltekit-oidc/compare/v1.6.3...v1.6.4) (2026-06-27)


### Bug Fixes

* **security:** harden oidc session handling ([660fe7c](https://github.com/SourceRegistry/sveltekit-oidc/commit/660fe7c8876e7176f2b2631fea6afe98d49fef5f))

## [1.6.3](https://github.com/SourceRegistry/sveltekit-oidc/compare/v1.6.2...v1.6.3) (2026-06-27)


### Bug Fixes

* **docs:** hook ([4de9d8a](https://github.com/SourceRegistry/sveltekit-oidc/commit/4de9d8ae23b7ad0e26092c7d5d243f82706648cc))

## [1.6.2](https://github.com/SourceRegistry/sveltekit-oidc/compare/v1.6.1...v1.6.2) (2026-06-27)


### Bug Fixes

* **dependencies:** update and added hook ([ee00dfd](https://github.com/SourceRegistry/sveltekit-oidc/commit/ee00dfd804cd504267b7aa08c3bd6843a412cf7a))

## [1.6.1](https://github.com/SourceRegistry/sveltekit-oidc/compare/v1.6.0...v1.6.1) (2026-06-19)


### Bug Fixes

* revalidate before redirecting on token expiry ([29bc6c2](https://github.com/SourceRegistry/sveltekit-oidc/commit/29bc6c20549cbc8e2d1d42503e4df7c25358605f))

# [1.6.0](https://github.com/SourceRegistry/sveltekit-oidc/compare/v1.5.0...v1.6.0) (2026-06-19)


### Features

* **example:** migrate to new typing system ([cf220ee](https://github.com/SourceRegistry/sveltekit-oidc/commit/cf220ee83f7cb59318da798cf0ad8c37dbf53f59))

# [1.5.0](https://github.com/SourceRegistry/sveltekit-oidc/compare/v1.4.0...v1.5.0) (2026-06-19)


### Bug Fixes

* scope package references and export infer types from client ([8e212c4](https://github.com/SourceRegistry/sveltekit-oidc/commit/8e212c47816a47949f1f4db6167784efbd3aabdf))


### Features

* infer TClaims from App.Locals in useOIDC and getOIDCContext ([fabc603](https://github.com/SourceRegistry/sveltekit-oidc/commit/fabc60355be19783efd0baefe1216bb0dde8f665))

# [1.4.0](https://github.com/SourceRegistry/sveltekit-oidc/compare/v1.3.1...v1.4.0) (2026-06-19)


### Features

* add OIDCLocals helper type and update docs ([5a7f324](https://github.com/SourceRegistry/sveltekit-oidc/commit/5a7f324c06512d8fa45bb853cfd3a6a919bb085b))
* ergonomic createOIDC options and structured logging ([9b5c6df](https://github.com/SourceRegistry/sveltekit-oidc/commit/9b5c6dfa35993f2238bb5bac7cb86ddf046be634))

## [1.3.1](https://github.com/SourceRegistry/sveltekit-oidc/compare/v1.3.0...v1.3.1) (2026-06-13)


### Bug Fixes

* **release:** update ([29f8476](https://github.com/SourceRegistry/sveltekit-oidc/commit/29f8476c4c459a981a86987283daa69a1ee0306f))

# [1.3.0](https://github.com/SourceRegistry/sveltekit-oidc/compare/v1.2.0...v1.3.0) (2026-06-08)


### Features

* generic TSession for typed custom OIDC sessions end-to-end ([ed8c756](https://github.com/SourceRegistry/sveltekit-oidc/commit/ed8c7565526c1797a7ff824cbcc7ad8030e84f9a))

# [1.2.0](https://github.com/SourceRegistry/sveltekit-oidc/compare/v1.1.1...v1.2.0) (2026-06-08)


### Features

* generic TClaims for typed custom OIDC claims end-to-end ([ec68e75](https://github.com/SourceRegistry/sveltekit-oidc/commit/ec68e753f80849e01016056ad283701614624b37))

## [1.1.1](https://github.com/SourceRegistry/sveltekit-oidc/compare/v1.1.0...v1.1.1) (2026-04-06)


### Bug Fixes

* added clockSkewSeconds to options ([1683fe9](https://github.com/SourceRegistry/sveltekit-oidc/commit/1683fe9a4a1558e4fef21a02f0fedb88103336f0))

# [1.1.0](https://github.com/SourceRegistry/sveltekit-oidc/compare/v1.0.4...v1.1.0) (2026-04-06)


### Features

* add server-backed session storage ([c5f1d46](https://github.com/SourceRegistry/sveltekit-oidc/commit/c5f1d465669f7a829e3ffb4a1ce34e4af1d41b6a))

## [1.0.4](https://github.com/SourceRegistry/sveltekit-oidc/compare/v1.0.3...v1.0.4) (2026-04-06)


### Bug Fixes

* preserve discovered jwks uri ([5ccb576](https://github.com/SourceRegistry/sveltekit-oidc/commit/5ccb5763fa4b5049e395eabd5a2e671f70529540))

## [1.0.3](https://github.com/SourceRegistry/sveltekit-oidc/compare/v1.0.2...v1.0.3) (2026-04-06)


### Bug Fixes

* packaging scope ([a881ae6](https://github.com/SourceRegistry/sveltekit-oidc/commit/a881ae69c0addbd689289810fed158986c315c99))

## [1.0.2](https://github.com/SourceRegistry/sveltekit-oidc/compare/v1.0.1...v1.0.2) (2026-04-06)


### Bug Fixes

* packaging scope ([94b6dcb](https://github.com/SourceRegistry/sveltekit-oidc/commit/94b6dcb2711d9ad43e18ef6ef9efc3d5e5db95c5))

## [1.0.1](https://github.com/SourceRegistry/sveltekit-oidc/compare/v1.0.0...v1.0.1) (2026-04-06)


### Bug Fixes

* docs and packaging ([304c5b3](https://github.com/SourceRegistry/sveltekit-oidc/commit/304c5b3523067f27453abebc6758e70e4be19f92))

# 1.0.0 (2026-04-06)


### Features

* prepare initial release ([71e368a](https://github.com/SourceRegistry/sveltekit-oidc/commit/71e368a22b6e006172a5f10c9d972d9601d63df3))
