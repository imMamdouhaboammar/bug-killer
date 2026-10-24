# Bug Killer Remediation & Patching Strategies

This reference details the four core remediation strategies implemented by Bug Killer (`bk`).

---

## 1. Strategy A: Reverse Proxy Virtual Patching (WAF Injection)

### Target Technologies
- Nginx, Apache HTTP Server, HAProxy.

### Mechanism
- Injects HTTP 415 `Unsupported Media Type` rejection rules for requests carrying vulnerable compressed payloads (such as `Content-Encoding: br` for Node2Shell or corrupted fastcgi streams for PHP2Shell).
- Intercepts and rejects malicious payloads at the edge before requests reach backend application processes.

### Idempotency
- The injector checks whether the mitigation rule already exists. If present, it logs a no-op and avoids duplicate configuration directives.

---

## 2. Strategy B: Dependency Manifest Pinning

### Target Files
- `package.json`, `composer.json`, `Cargo.toml`, `requirements.txt`.

### Mechanism
- Identifies unpatched dependency versions and updates the version constraint to the minimum safe upstream release:
  - Node.js engines pinned to `>= 22.23.4`, `>= 24.22.1`, or `>= 26.12.1`.
  - PHP engine constraints pinned to safe patch branches (`>= 8.2.35`, `>= 8.3.36`, `>= 8.4.27`, `>= 8.5.12`).
- Preserves existing formatting, quotes, and indentation.

---

## 3. Strategy C: Container Hardening (Dockerfile)

### Target Files
- `Dockerfile`, `docker-compose.yml`.

### Mechanism
- Bumps vulnerable base image tags to patched security releases (e.g. `node:22-alpine` -> `node:22.23.4-alpine`).
- Enforces non-root container execution by inserting `USER 10001:10001` before the entrypoint.
- Replaces insecure shell execution pipes (`curl ... | sh`) with multi-stage verified package installations.

---

## 4. Strategy D: Application Middleware Guarding

### Target Frameworks
- Express.js, Fastify, Koa, Laravel, Symfony.

### Mechanism
- Inserts defensive middleware in the request handling pipeline that validates incoming decompression headers and rejects unauthenticated compressed request bodies pending binary runtime upgrades.
