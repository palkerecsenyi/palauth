FROM node:18

WORKDIR /usr/src/app

RUN npm install -g node-gyp
COPY package.json yarn.lock ./
RUN yarn install --immutable --check-cache

COPY . .
RUN yarn db:generate
RUN yarn build

CMD ["yarn", "prod"]