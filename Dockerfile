FROM node:18

WORKDIR /usr/src/app

COPY package.json yarn.lock ./
RUN npm install -g node-gyp
RUN yarn install --immutable --check-cache

COPY . .
RUN yarn build

CMD ["yarn", "prod"]