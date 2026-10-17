# u2i-dev-idp

A generalized, **deliberately unsecured** OpenID Connect / OAuth2 identity
provider for lower environments (local dev, qa, per-PR preview).

It lets any of our apps authenticate without a real Google (or other)
OAuth callback. There is **no security** here by design: it accepts any
`client_id`, any `redirect_uri`, any `scope`, and lets you sign in as
anyone by simply typing a username. It is meant to run **behind a
perimeter** (e.g. the cluster-edge OAuth gate) and **must never be
deployed to production**.

## Why

Our deployed environments (dev/qa/preview/prod) are one prod-built
artifact differentiated only by runtime config, so we can't compile real
Google OAuth out of lower envs. Rather than special-case each app, this
single shared service stands in for the IdP: point an app's OAuth/OIDC
config at it in lower envs, log in as anyone, and the app's *real* auth
code path runs unchanged.

## Endpoints

| Method | Path                                | Purpose                              |
|--------|-------------------------------------|--------------------------------------|
| GET    | `/.well-known/openid-configuration` | OIDC discovery                       |
| GET    | `/authorize`                        | login picker → redirect with `code`  |
| POST   | `/login`                            | picker form target                   |
| POST   | `/token`                            | `code` → `{access_token, id_token}`  |
| GET    | `/userinfo`                         | bearer token → claims                |
| GET    | `/jwks`                             | RS256 signing public key             |
| GET    | `/healthz`                          | liveness                             |

It serves both plain OAuth2 (authorize/token/userinfo) and full OIDC
(discovery + signed `id_token` + JWKS), so it works for either kind of
client.

## Identity model

Type a bare username → `<username>@<DEFAULT_EMAIL_DOMAIN>`. Type a full
email → used verbatim, `hd` taken from its domain. `email_verified` is
always `true`. `firstname.lastname` usernames get `given_name` /
`family_name` / `name` derived.

Extra query/form params flow through as claims, so role-gated apps can be
exercised — e.g. `?groups=hr` (comma-separated → list), or `?domain=...`
to override the email domain for one login.

## Config

| Env var                | Default                  | Meaning                                  |
|------------------------|--------------------------|------------------------------------------|
| `ISSUER`               | `http://localhost:8080`  | public base URL (used in tokens + URLs)  |
| `DEFAULT_EMAIL_DOMAIN` | `u2i.com`                | domain for bare usernames                |
| `PORT`                 | `8080`                   | listen port                              |

The RS256 signing key is generated fresh on each boot — there are no
secrets to manage. Tokens don't survive a restart, which is fine for a
dev IdP.

## Run locally

```sh
mise install                      # installs the pinned Go toolchain
go run .                          # or: go build -o idp . && ./idp
# open http://localhost:8080/authorize?redirect_uri=http://localhost:3000/cb&state=x
```

## Image

Published to GitHub Container Registry by `.github/workflows/docker.yml`
(multi-arch `linux/amd64` + `linux/arm64`, ~17MB distroless/static):

```
ghcr.io/u2i/mock-idp:latest     # latest vX.Y.Z release tag
ghcr.io/u2i/mock-idp:0.1.0      # pushed by git tag v0.1.0
ghcr.io/u2i/mock-idp:main       # tip of main
ghcr.io/u2i/mock-idp:sha-<sha>  # every push to main
```

Cut a release with:

```sh
git tag v0.1.1 && git push origin v0.1.1
```

Pin to a digest in any long-lived consumer; `:latest`/`:main` are for
development. The deployed instance lives at **mock-idp.u2i.dev** (chart in
`u2i-infra`, nonprod only).

## Pointing an app at it

Set the app's OAuth/OIDC endpoints to the deployed `ISSUER`
(`https://mock-idp.u2i.dev`):

- `authorize_url` → `${ISSUER}/authorize`
- `token_url`     → `${ISSUER}/token`
- `user_url`      → `${ISSUER}/userinfo`
- (OIDC) discovery/issuer → `${ISSUER}`

`client_id` / `client_secret` can be any non-empty values — they're not
checked.
