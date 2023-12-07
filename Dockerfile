FROM node:20-alpine

WORKDIR /usr/src/app

RUN npm install -g node-gyp
COPY package.json yarn.lock ./
RUN yarn install


COPY . .
RUN yarn db:generate
RUN yarn build

COPY webauthn-frontend/package.json ./webauthn-frontend/
WORKDIR /usr/src/app/webauthn-frontend
RUN yarn install
RUN yarn build-prod

WORKDIR /usr/src/app
CMD ["yarn", "prod"]
