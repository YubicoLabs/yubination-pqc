# SimpleWebAuthn v14.0.2 example server, configured to request PQC ML-DSA passkeys.
#
# Node 24.7.0+ is required: @simplewebauthn/server detects ML-DSA support through
# SubtleCrypto.supports(), which older runtimes don't have. node:24-alpine currently
# ships 24.20.x / OpenSSL 3.5.x, which satisfies that.
FROM node:24.22.0-alpine

WORKDIR /app

COPY app/package.json app/package-lock.json ./
RUN npm ci --omit=dev

COPY app/index.ts app/types.d.ts app/tsconfig.json ./
COPY app/public ./public
COPY app/licenses ./licenses

# Serve the WebAuthn browser bundle from the container rather than a CDN, so the
# client and server halves of SimpleWebAuthn can't drift apart.
RUN cp node_modules/@simplewebauthn/browser/dist/bundle/index.umd.min.js public/browser.umd.min.js

ENV NODE_ENV=production \
    PORT=8010 \
    RP_ID=localhost

EXPOSE 8010

USER node

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s \
  CMD wget -qO- "http://127.0.0.1:${PORT}/config" > /dev/null || exit 1

# Node 24 strips the TypeScript types natively; no build step, no ts-node.
CMD ["node", "index.ts"]
