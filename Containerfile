FROM docker.io/oven/bun:alpine

WORKDIR /usr/src/app

COPY package.json bun.lockb ./
COPY packages/backend/package.json ./packages/backend/package.json
COPY packages/webauthn-frontend/package.json ./packages/webauthn-frontend/package.json

RUN bun install

COPY . .
RUN bun run --cwd packages/webauthn-frontend build-prod
RUN bun run --cwd packages/backend db:generate
RUN bun run --cwd packages/backend build

WORKDIR /usr/src/app
CMD ["bun", "run", "--cwd", "packages/backend", "prod"]
