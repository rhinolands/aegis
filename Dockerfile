# syntax=docker/dockerfile:1

# ---- build ----
FROM node:22-bookworm-slim AS build
WORKDIR /app

# opa for the wasm build.
#
# This is a native (non-cross) build: the build stage runs on whatever
# architecture `docker build` is invoked on, so `uname -m` inside the stage
# always reflects the real build architecture — unlike a hardcoded
# opa_linux_amd64_static download, which silently produces a non-executable
# binary on arm64 hosts (Apple Silicon).
RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates \
  && ARCH="$(uname -m)" \
  && case "$ARCH" in \
       x86_64) OPA_ARCH=amd64 ;; \
       aarch64|arm64) OPA_ARCH=arm64 ;; \
       *) echo "unsupported build architecture: $ARCH" >&2; exit 1 ;; \
     esac \
  && curl -L -o /usr/local/bin/opa "https://openpolicyagent.org/downloads/latest/opa_linux_${OPA_ARCH}_static" \
  && chmod +x /usr/local/bin/opa \
  && rm -rf /var/lib/apt/lists/*

COPY package*.json ./
RUN npm ci
COPY . .
RUN npm run build            # build:policy (opa build -t wasm) + tsc; emits dist/policy.wasm

# ---- runtime ----
FROM node:22-bookworm-slim AS runtime
WORKDIR /app
ENV NODE_ENV=production

# drizzle-kit is a production dependency of this image (not just a dev tool):
# the Helm chart's pre-install/pre-upgrade migration Job runs this same image
# with `npx drizzle-kit migrate`, and it must resolve from node_modules rather
# than reaching out to the npm registry from inside the cluster.
COPY package*.json ./
RUN npm ci --omit=dev && npm cache clean --force

COPY --from=build --chown=node:node /app/dist ./dist
COPY --from=build --chown=node:node /app/migrations ./migrations
COPY --from=build --chown=node:node /app/drizzle.config.ts ./drizzle.config.ts

USER node
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:'+(process.env.PORT||8080)+'/health').then(r=>{if(!r.ok)process.exit(1)}).catch(()=>process.exit(1))"

CMD ["node", "dist/index.js"]
