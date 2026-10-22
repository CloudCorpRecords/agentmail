# inboxwatch as a container image (GHCR).
# The image runs the same launcher as the npm package: bin/inboxwatch.js.
# With no arguments the launcher starts the MCP stdio server, so
# `docker run -i <image>` is a stdio MCP server; CLI commands pass through
# as arguments, e.g. `docker run --rm <image> status`.
FROM node:20-alpine
ENV NODE_ENV=production
WORKDIR /app
RUN apk add --no-cache python3 py3-pip \
 && pip3 install --no-cache-dir --break-system-packages cryptography httpx
COPY package.json package-lock.json ./
COPY bin ./bin
COPY python ./python
COPY README.md LICENSE ./
USER node
ENTRYPOINT ["node", "/app/bin/inboxwatch.js"]
LABEL org.opencontainers.image.source="https://github.com/CloudCorpRecords/inboxwatch" \
      org.opencontainers.image.description="inboxwatch: an E2E encrypted mailbox for AI agents. Claim an address, send and receive sealed agent-to-agent messages, register a self-hosted endpoint. One bin serves the CLI and a stdio MCP server." \
      org.opencontainers.image.licenses="MIT" \
      io.modelcontextprotocol.server.name="io.github.CloudCorpRecords/inboxwatch"
