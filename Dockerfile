# syntax=docker/dockerfile:1

FROM node:22-alpine@sha256:16e22a550f3863206a3f701448c45f7912c6896a62de43add43bb9c86130c3e2

# Install dependencies
RUN apk add --no-cache \
    bash \
    curl \
    git \
    openssl \
    ca-certificates

WORKDIR /app

# Copy package files
COPY package*.json ./
COPY tsconfig.json ./

# Install dependencies
RUN npm ci && \
    npm cache clean --force

# Copy source code
COPY . .

# Build TypeScript
RUN npm run build

# Ensure docs directory exists for /ui static files
RUN mkdir -p docs

# Docker environment marker (tells server.ts to bind to 0.0.0.0)
ENV DOCKER=true

# Expose port
EXPOSE 3333

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://localhost:3333/api/health || exit 1

# Default command: run the compiled prod server (tsx loader is dev-only and unstable in containers)
CMD ["npm", "run", "server:prod"]
