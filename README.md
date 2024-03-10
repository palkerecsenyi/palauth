# PalAuth

PalAuth is an authentication and IAM provider with support for OIDC. It's similar to [Keycloak](https://www.keycloak.org/) but aims to be simpler and easier to install/maintain.

Here are some features:

- Secure password authentication using argon2id
- (Relatively) easy set up process with a ready-made Dockerfile
- Support for TOTP and Webauthn based 2FA
- Support for passkeys (passwordless sign-in with Webauthn)
- RBAC IAM with a user-friendly dashboard and a REST HTTP API
- Sessions stored in Redis
- Uses MySQL with Prisma schemas for an easy development experience

# Installation

## Prerequisites

- You need a MySQL database. You can set the database name and credentials to be whatever you'd like, as you will need to supply a full database URL to PalAuth.
    - Make sure to run migrations for this database by running `bun run --cwd packages/backend db:migrate:prod` with the `PAL_DB_STRING` environment variable specified. Currently, these have to be run manually; PalAuth will not run them for you, even if there are new migrations required.
- You need a Redis instance.
- You need a self-hosted [friendly-lite-server](https://github.com/FriendlyCaptcha/friendly-lite-server).

## From source

### Node JS
1. Clone this repository
2. Run `bun install`
3. Run `bun run --cwd packages/webauthn-frontend build-prod`
4. Run `bun run --cwd packages/backend db:generate`
5. Run `bun run --cwd packages/backend build`
6. Configure (see below)
7. Run `bun run --cwd packages/backend prod`

### Docker
1. Clone this repository
2. Build the Docker image using the Dockerfile
3. Configure the environment variables
4. Run!

## From Docker Hub
PalAuth is available as `ghcr.io/palkerecsenyi/palauth`. For now, this only has one tag `latest`, with images available for `linux/amd64` and `linux/arm64/v8`.

## On Kubernetes
As a containerised app, you can easily deploy PalAuth on Kubernetes. The configuration used at auth.palk.me is available in `k8s/deployment.yaml`.

# Configuration
Currently, PalAuth can be configured through a number of environment variables prefixed with `PAL_`.

These are all the available options:

- `PAL_DB_STRING`: The SQL connection string. See [Prisma docs](https://www.prisma.io/docs/concepts/database-connectors/mysql#connection-url)
- `PAL_HOSTNAME`: The hostname PalAuth will be running on (e.g. `example.com`)
- `PAL_OIDC_ID`: The Provider ID of the OIDC subsystem. Usually similar to the hostname but must be a full URL. E.g. `https://example.com`
- `PAL_CAPTCHA_URL`: URL of a [Friendly Captcha](https://friendlycaptcha.com/) server. Currently only the self-hosted [friendly-lite-server](https://github.com/FriendlyCaptcha/friendly-lite-server) is supported.
- `PAL_CAPTCHA_KEY`: API key of the Friendly Captcha server.
- `PAL_SECRET`: A secret used for session and CSRF signing.
- `PAL_PUBLIC_JWK`: A base64-encoded RS256 [JWK](https://www.rfc-editor.org/rfc/rfc7517) public key. You can generate these at [mkjwk](https://mkjwk.org/) (for example)
- `PAL_PRIVATE_JWK`: The corresponding base64-encoded JWK private key
- `PAL_MAILGUN_KEY`: An API key for Mailgun, used for sending account emails
- `PAL_MAILGUN_HOST`: The host to send Mailgun emails from
- `PAL_REDIS_URL`: A Redis connection string including credentials, used for session storage

- `NODE_ENV`: `production` or `development`

## Development variables
You can use these variables in development to make your life easier:

- `PAL_DEV_CAPTCHA_DISABLE`: `true` or `false` — disables captchas
- `PAL_DEV_ALLOW_INSECURE_PASSWORD`: `true` or `false` — disabled password security requirements
- `PAL_DEV_SKIP_EMAIL_VERIFICATION`: `true` or `false` — skips email verification for new accounts

# License
GNU GPL 3.0. See `LICENSE.md`.
