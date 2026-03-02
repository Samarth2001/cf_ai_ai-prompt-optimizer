# Codebase Review — AI Prompt Optimizer

**Date:** 2026-03-02
**Scope:** Full codebase review (extension + Cloudflare Worker API)

---

## Summary

The AI Prompt Optimizer is a well-architected Chrome extension with a solid security foundation: AES-GCM encryption for stored keys, JWT authentication, multi-layer rate limiting via Durable Objects, and server-side system prompt injection. The code is functional and security-conscious.

That said, there are several areas where the codebase can be improved in terms of **code duplication, consistency, maintainability, security hardening, and testing**. Below are the findings ordered by priority.

---

## Critical / High Priority

### 1. Massive code duplication in `api/src/index.ts` (1,359-line monolith)

The `/api/enhance` and `/api/enhance/byok` endpoints share ~90% identical code:

- **Rate-limiting middleware** (lines 501–564 vs. 1075–1138): Nearly identical ~60-line blocks.
- **Enhance handler logic** (lines 839–1069 vs. 1140–1357): Nearly identical ~200-line blocks covering schema validation, body parsing, size checks, upstream fetch, error handling, usage tracking, and response building.
- **Zod schemas** are defined inline in both handlers with the only difference being the `byokKey` field.

**Suggestion:** Extract a shared `handleEnhanceRequest(c, apiKey, origin)` function and a shared rate-limiting middleware factory. The BYOK handler just adds key extraction from the body before calling the shared logic.

```typescript
// Example refactor sketch
function createRateLimitMiddleware(path: string) { /* shared logic */ }
async function handleEnhance(c: any, apiKey: string, origin: string) { /* shared logic */ }

app.post("/api/enhance", async (c) => {
  const key = c.env.OPENROUTER_API_KEY;
  return handleEnhance(c, key, c.get("corsOrigin"));
});

app.post("/api/enhance/byok", async (c) => {
  const body = /* parse + validate */;
  return handleEnhance(c, body.byokKey, c.get("corsOrigin"));
});
```

### 2. Duplicate rate-limit update logic in `service-worker.js`

`handleProxyRequest` (lines 402–450) and `handleByokRequest` (lines 524–571) contain ~40 identical lines for parsing rate-limit headers and updating storage. Extract this into a shared `updateRateLimitFromResponse(response)` function.

### 3. Inconsistent error response shape between proxy and BYOK handlers

- `handleProxyRequest` sends: `{ success: false, error: { message, status, data } }` (object)
- `handleByokRequest` sends: `{ success: false, error: "string message" }` (string)

This means `formatErrorMessage()` in `content.js` can't reliably extract status codes or error codes from BYOK errors — the `status === 429` check will never match.

**Suggestion:** Normalize both handlers to return the same error shape.

### 4. Duplicate `logServerError` call

`api/src/index.ts` lines 1014–1018:
```typescript
if (response.status >= 500) {
  logServerError(c, "UPSTREAM_ERROR");
}
if (response.status >= 500) {   // exact duplicate
  logServerError(c, "UPSTREAM_ERROR");
}
```

This logs the same error twice. Remove the duplicate block.

---

## Medium Priority

### 5. Hardcoded API URL across the extension

The URL `https://prompt-enhancer-worker.prompt-enhance-api.workers.dev` appears 6+ times in `service-worker.js` (lines 74, 129, 151, 234, 332, 383, 504). If the worker URL ever changes, you'd need to find and update every occurrence.

**Suggestion:** Extract to a single constant:
```javascript
const API_BASE = "https://prompt-enhancer-worker.prompt-enhance-api.workers.dev";
```

### 6. `decodeJwt` is duplicated

Identical implementations exist in both `service-worker.js:167` and `popup.js:57`. If one is updated, the other could easily be missed.

**Suggestion:** Move to a shared utility module (e.g., `utils/jwt-utils.js`) and import in both files.

### 7. `perplexity.ai` missing from default ALLOWED_HOSTS

`service-worker.js:19-25` defines `DEFAULTS.ALLOWED_HOSTS` but omits `perplexity.ai`, even though:
- It's in `manifest.json` content scripts
- It's in `SITE_STYLES` and `SITE_SELECTORS`

This means on first install (before remote config loads), the enhance button on Perplexity won't work because `isTrustedSender` will reject messages from that origin.

### 8. Zod schemas recreated on every request

Both enhance handlers define the Zod schema inside the route handler, meaning it's rebuilt on every request. While the performance impact is small per request, it's unnecessary work on a hot path.

**Suggestion:** Define schemas at module level as constants.

### 9. `api/src/index.ts` should be split into modules

At 1,359 lines, the single-file API is hard to navigate. Suggested structure:
```
api/src/
  index.ts              # App setup + route registration
  durable-objects/
    rate-limiter.ts
    token-gate.ts
    usage-aggregator.ts
  middleware/
    cors.ts
    auth.ts
    rate-limit.ts
  routes/
    config.ts
    token.ts
    enhance.ts
    turnstile.ts
  utils/
    logging.ts
    headers.ts
    system-prompt.ts
```

### 10. Dead code: `SecureStorageService.clearApiKey()`

`secure-storage-service.js:280-282` removes `encrypted_api_key`, but the codebase consistently uses `byokApiKey` as the storage key. This method appears to be leftover from an earlier iteration and is never called.

### 11. `popup.js`: Unused `hasApiKey` parameter

`updateUIMode(mode, hasApiKey)` accepts a `hasApiKey` parameter but never reads it inside the function body. All callers compute and pass it unnecessarily.

---

## Low Priority / Code Quality

### 12. Empty catch blocks swallow errors silently

Multiple catch blocks discard errors without logging:
- `service-worker.js:249` (getUsage fetch failure — silent)
- `service-worker.js:449`, `570` (rateLimitUpdate message — silent)
- `api/src/index.ts:252` (UsageAggregator body parse — silent)
- `api/src/index.ts:1006`, `1300` (upstream payload parse — silent)
- `api/src/index.ts:1051`, `1339` (usage aggregator increment — silent)

While some of these are intentionally fire-and-forget, adding at least `console.warn` would help with debugging in production.

### 13. `ValidationService.sanitizeInput` has unreachable code

```javascript
sanitizeInput(input) {
  // ...
  const hasBinaryControls = /[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/.test(input);
  if (hasBinaryControls) {
    return '';           // Returns early
  }
  let sanitized = input;
  sanitized = sanitized.replace(/[\x00-\x1F\x7F]/g, '');  // Never reached if binary controls exist
```

The regex on line 6 matches a subset of what line 12 removes. If line 6 matches, the function returns empty immediately — so line 12 only handles `\x09` (tab), `\x0A` (LF), `\x0D` (CR), which are then handled by the tab and carriage-return replacements anyway. The early return is overly aggressive: a prompt containing a tab character gets entirely rejected rather than cleaned.

**Suggestion:** Remove the early return and let the normalization logic handle all cases gracefully.

### 14. Empty `else` block in `content.js:180`

```javascript
if (!wrapper) {
  wrapper = window.__PE_utils.createWrapper(textInput);
} else {
  // empty
}
```

Remove the empty `else` block.

### 15. `sanitizeText` in `content.js` is a no-op

```javascript
function sanitizeText(text) {
  if (typeof text !== "string") return text;
  const temp = document.createElement("div");
  temp.textContent = text;
  return temp.textContent;
}
```

Setting `textContent` and immediately reading it back returns the same string — `textContent` doesn't interpret HTML. This function creates a DOM element on every call for no effect. If the intent is HTML-entity encoding for display in `innerHTML`, the result is never used that way (toast messages use `textContent`).

### 16. `!important` in inline hover styles won't work

`content.js:152-154`:
```javascript
button.style.background = siteStyle.hoverBackground + " !important";
```

The `!important` flag is only valid in stylesheets, not in `element.style` assignments. The string `"linear-gradient(...) !important"` will be silently ignored by the browser, meaning hover effects set via JS won't apply. The CSS stylesheet already handles `:hover` correctly, so these JS event listeners are redundant.

---

## Security Considerations

### 17. Potential injection in Turnstile HTML templates

`api/src/index.ts:703`: The `redirect` URI and `siteKey` are interpolated into raw HTML/JS:
```javascript
const html = `...callback:function(t){location.href='${redirect}#token='+encodeURIComponent(t);}...`;
```

While `redirect` is validated against a regex (`/^https:\/\/[a-zA-Z0-9]+\.chromiumapp\.org\//`), if the regex were ever loosened, a `redirect` containing a single quote (`'`) could break out of the JavaScript string literal.

**Suggestion:** Use `JSON.stringify(redirect)` or `encodeURIComponent(redirect)` when interpolating into JavaScript context, and `encodeURI` for HTML attribute context, as a defense-in-depth measure.

### 18. BYOK API key in request body

The user's OpenRouter API key is sent in the JSON body (`byokKey` field). Any logging middleware that dumps request bodies would capture it. Consider using a custom header (e.g., `X-BYOK-Key`) instead, which is more commonly excluded from body-level logging.

### 19. No rate limiting on `/api/config` endpoint

The config endpoint has 12-hour caching but no rate limiting. An attacker could bypass the cache (e.g., with varying `Origin` headers) and hammer the endpoint. While the impact is low (it only returns public config), adding a basic rate limit would harden it.

---

## Testing

### 20. No test infrastructure exists

- `package.json` test script: `echo "Error: no test specified" && exit 1`
- Zero test files in the repository
- No test framework installed

**Recommended test coverage priorities:**
1. **`ValidationService`** — sanitization edge cases (control chars, unicode, length limits)
2. **`CryptoService`** — encrypt/decrypt round-trips, key derivation consistency
3. **`SecureStorageService`** — passphrase mode, key lifecycle
4. **API endpoint validation** — Zod schema boundary cases, error codes
5. **Rate limiter** — daily reset, counter increment, bypass logic
6. **`isTrustedSender`** — origin validation edge cases

**Suggested setup:** Vitest for both extension and worker tests (lightweight, native ESM, Cloudflare Workers support via `@cloudflare/vitest-pool-workers`).

---

## Summary Table

| # | Issue | Severity | Type |
|---|-------|----------|------|
| 1 | Massive duplication in enhance handlers (API) | High | Maintainability |
| 2 | Duplicate rate-limit update logic (service worker) | High | Maintainability |
| 3 | Inconsistent error response shape (proxy vs BYOK) | High | Bug |
| 4 | Duplicate `logServerError` call | High | Bug |
| 5 | Hardcoded API URL (6+ occurrences) | Medium | Maintainability |
| 6 | Duplicated `decodeJwt` function | Medium | Maintainability |
| 7 | Missing `perplexity.ai` in default ALLOWED_HOSTS | Medium | Bug |
| 8 | Zod schemas recreated per request | Medium | Performance |
| 9 | 1,359-line monolith API file | Medium | Maintainability |
| 10 | Dead `clearApiKey()` method | Medium | Dead code |
| 11 | Unused `hasApiKey` parameter | Low | Dead code |
| 12 | Empty catch blocks | Low | Debuggability |
| 13 | Unreachable sanitization code | Low | Logic bug |
| 14 | Empty `else` block | Low | Code quality |
| 15 | No-op `sanitizeText` function | Low | Dead code |
| 16 | `!important` in inline styles (broken) | Low | Bug |
| 17 | Template injection risk in Turnstile HTML | Low | Security |
| 18 | BYOK key in request body | Low | Security |
| 19 | No rate limit on `/api/config` | Low | Security |
| 20 | Zero test coverage | Medium | Testing |
