FROM node:22-alpine AS builder

WORKDIR /app

ENV CI=true

RUN corepack enable

COPY package.json pnpm-lock.yaml .npmrc ./

RUN pnpm install --frozen-lockfile --ignore-scripts

COPY . .

RUN pnpm build

FROM node:22-alpine

WORKDIR /app

ENV NODE_ENV=production
ENV CI=true
ENV BACKEND_URL=http://dashboard:5000

RUN corepack enable

COPY --from=builder /app ./

EXPOSE 3000

CMD ["pnpm", "start"]