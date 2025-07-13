FROM ghcr.io/downunderctf/eth-challenge-base/geth:latest as geth

FROM node:20-alpine as ui

WORKDIR /app
COPY ui/*.* ./
RUN npm install
COPY ui/src ./src
RUN npm run build

FROM node:20-alpine

COPY --from=geth / /geth
COPY --from=geth /usr/local/bin/geth /usr/local/bin/geth
WORKDIR /app
COPY package.json package-lock.json tsconfig.json ./
RUN npm install 

COPY example/challenge.yaml challenge.yaml
COPY example/contracts/ contracts
COPY example/build/ build
COPY --from=ui /app/dist ./static
COPY src/ src/
RUN npm run build

EXPOSE 3000
EXPOSE 8545
COPY entrypoint.sh entrypoint.sh
COPY challenge.yaml challenge.yaml
ENTRYPOINT ["sh", "entrypoint.sh"]