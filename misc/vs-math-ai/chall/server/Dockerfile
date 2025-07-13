FROM node:22-alpine

WORKDIR /app

COPY package*.json ./
RUN corepack enable
RUN pnpm install

COPY . .

# Make files read-only but keep directories executable
RUN find /app -type f -exec chmod 444 {} \;
RUN find /app -type d -exec chmod 555 {} \;

RUN addgroup -g 1001 -S user
RUN adduser -S user -u 1001

USER user

EXPOSE 3000

CMD ["node", "index.js"]