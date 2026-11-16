# sidedoor head-to-head (2026-11-17)

Real target, not a toy: **nginx 1.27 → Tomcat 10.1** via docker-compose
(`h2h-lab/`). The edge denies `/admin` (403); Tomcat serves a secret panel
(380b) reachable through the Orange-Tsai `;`/`..;` path-normalization gap.
Ground truth, verified with plain curl before any tool ran:

- `/admin`            -> 403 (153b)   baseline denial
- `/admin;/`          -> 200 (380b)   REAL bypass
- `/x/..;/admin/`     -> 200 (380b)   REAL bypass (classic)
- random path         -> 404 (767b)   not a wildcard

## Result on `http://127.0.0.1:8080/admin`

| Tool | Found real bypass? | Lines of output | False positives | Notes |
|------|--------------------|-----------------|-----------------|-------|
| **sidedoor** | yes (`/admin;/`, +95) | **3** (1 real + 2 redirect leads) | **0** | root-page + empty-body controls suppress the noise |
| **nomore403** (defaults) | yes (`/admin/;%2f..%2f..%2f`, `100!`) | ~50 | ~45 low-score 404/403/400 "variations" + HEAD | ranks real hit #1; cleans up with `--status 200` / summary |

## Honest verdict

- **Tie on finding.** Both reached the protected resource; neither missed it.
- **sidedoor wins default signal-to-noise.** Its scoring treats a `404`-with-different-
  length as not-a-hit, so it stays quiet where nomore403 lists ~45 length-variation
  entries by default.
- **nomore403 wins breadth.** Larger, more creative payload set (`%5c`, `%0d`, deeper
  double-encoding, raw desync, HTTP-version tricks) + more features. On a harder
  target one of those may be the only thing that works, and sidedoor would miss it.

So sidedoor's claim is **"reliable, low-noise, good default" — not "finds more."**

## What this still does NOT prove

A lab is a constructed state. This shows behaviour on one faithfully-built stack,
not efficacy across the real heterogeneous web. The remaining gap closes only with
runs against authorized real targets.

## FP classes the real lab caught (and sidedoor now fixes)

The toy lab (`testlab/server.py`) never exposed these — the real multi-page app did:
1. **rewrite-header FP** — probing `/` with `X-Original-URL: /admin` returns the
   public homepage (200); flagged as a bypass though the header did nothing.
   Fixed by the root-page control (suppress hits whose body == site root).
2. **path-resolves-to-root FP** — `/;admin` resolves to `/` on Tomcat -> homepage.
   Same fix.
3. **HEAD empty-body FP** — HEAD has no body, so body-length always differs from a
   GET baseline. Fixed by the empty-body guard in the weak-signal branch.
