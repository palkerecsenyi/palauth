FROM node:20-alpine

WORKDIR /usr/src/app

RUN apk add python3
RUN npm install -g node-gyp
COPY package.json yarn.lock .yarnrc.yml ./
COPY packages/backend/package.json ./packages/backend/package.json
COPY packages/webauthn-frontend/package.json ./packages/webauthn-frontend/package.json

RUN yarn set version stable
RUN yarn config set enableGlobalCache false
RUN yarn config set nodeLinker node-modules
RUN yarn install

COPY . .
RUN yarn workspace @paltiverse/palauth-webauthn-frontend build-prod
RUN yarn workspace @paltiverse/palauth-backend db:generate
RUN yarn workspace @paltiverse/palauth-backend build

WORKDIR /usr/src/app
CMD ["yarn", "workspace", "@paltiverse/palauth-backend", "prod"]
