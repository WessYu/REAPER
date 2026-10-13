FROM node:22-bookworm-slim AS build
WORKDIR /app
COPY package.json package-lock.json tsconfig.json eslint.config.js ./
COPY src ./src
COPY platform ./platform
RUN npm ci --ignore-scripts
RUN npm run build && npm run platform:build

FROM node:22-bookworm-slim AS runtime
WORKDIR /app
ENV NODE_ENV=production
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --ignore-scripts && npm cache clean --force
COPY --from=build /app/dist ./dist
COPY --from=build /app/platform/dist ./platform/dist
COPY --from=build /app/platform/config ./platform/config
RUN useradd --system --uid 65532 --home /nonexistent --shell /usr/sbin/nologin reaper
USER 65532:65532
ENTRYPOINT ["node", "/app/platform/dist/container-entry.js"]
