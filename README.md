# PalAuth

PalAuth is an authentication and IAM provider with support for OIDC. It's similar to [Keycloak](https://www.keycloak.org/) but is **not** written in Java.

Here are some features:

- Secure password authentication using argon2id
- (Relatively) easy set up process with a ready-made Dockerfile
- Support for TOTP and Webauthn based 2FA
- Support for passkeys
- RBAC IAM with a user-friendly dashboard and a REST HTTP API
- Sessions stored in Redis
- Uses MySQL with Prisma schemas for an easy development experience

# Installation and setup

1. Clone this repository
2. Build the Docker image using the Dockerfile
3. Configure the environment variables
4. Run!

## Environment variables and keys

- `PAL_DB_STRING`: The SQL connection string. See [Prisma docs](https://www.prisma.io/docs/concepts/database-connectors/mysql#connection-url)
- `PAL_HOSTNAME`: The hostname PalAuth will be running on (e.g. `example.com`)
- `PAL_OIDC_ID`: The Provider ID of the OIDC subsystem. Usually similar to the hostname but must be a full URL. E.g. `https://example.com`
- `PAL_CAPTCHA_URL`: URL of a [Friendly Captcha](https://friendlycaptcha.com/) server. You can either self-host or use the cloud-based version.
- `PAL_CAPTCHA_KEY`: API key of the Friendly Captcha server.
- `PAL_SECRETS`: A JSON string array of secrets used for session and CSRF token signing. The first key in the array will be used to sign new sessions, and other keys will be used to verify existing sessions. E.g. `["secret1", "secret2"]`
- `PAL_PUBLIC_JWK`: A base64-encoded RS256 [JWK](https://www.rfc-editor.org/rfc/rfc7517) public key. You can generate these at [mkjwk](https://mkjwk.org/) (for example)
- `PAL_PRIVATE_JWK`: The corresponding base64-encoded JWK private key
- `PAL_MAILGUN_KEY`: An API key for Mailgun, used for sending account emails
- `PAL_REDIS_URL`: A Redis connection string including credentials, used for session storage

- `NODE_ENV`: `production` or `development`

### Development variables
You can use these variables in development to make your life easier:

- `PAL_DEV_CAPTCHA_DISABLE`: `true` or `false` — disables captchas
- `PAL_DEV_ALLOW_INSECURE_PASSWORD`: `true` or `false` — disabled password security requirements
- `PAL_DEV_SKIP_EMAIL_VERIFICATION`: `true` or `false` — skips email verification for new accounts
