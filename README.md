# sidedoor — Slybrick 403/401 bypass scanner

A small, reliable access-control-bypass tester, by **Slybrick**. It does not try
to be the biggest toolbox in the space — it tries to be the one that gives you a
**trustworthy answer**: calibrate a baseline, fire the proven bypass techniques,
and only report a hit that measurably differs from both the baseline **and** a
decoy response. Every hit prints the exact `curl` to reproduce it.

**Authorized testing only.** Use this against targets you own or have explicit
permission to test (bug-bounty scope, a pentest engagement, your own infra).
Unauthorized use may be illegal — the responsibility is yours.

## Why it's reliable, not maximal

- **Two-shot baseline calibration** — fires the original request twice to measure
  natural response jitter, then sets a length tolerance from it. Dynamic pages
  (CSRF tokens, timestamps) don't produce phantom hits.
- **Decoy / wildcard detection** — probes a random path first. If the host answers
  a made-up path with `<400`, every "200" is filtered against that decoy so a
  catch-all homepage isn't reported as a bypass.
- **Scored, not dumped** — a denial that turns into a `2xx` scores highest; a `3xx`
  lower; a same-status body that moved beyond jitter is a weak lead. You read a
  ranked shortlist, not a wall.
- **Stack fingerprinting** — reads the baseline's `Server`/`X-Powered-By`/cookies and
  prunes payloads that physically can't apply (e.g. servlet `;` path-parameter tricks
  on a PHP or Node backend). Conservative: when the stack is unknown it fires everything.
- **Rate-limit aware** — retries `429`/`503` with exponential backoff, refuses to
  calibrate on a throttled baseline, and warns when a run is heavily throttled so you
  don't trust a WAF-corrupted result. `--delay` paces requests to stay under the limit.
- **Nondeterminism guard** — if the baseline's status flaps between two calibration
  shots, every comparison is void, so it says so and skips rather than inventing hits.
- **Single static binary** — Rust + `rustls` (no OpenSSL). Builds and runs the same
  on Linux/macOS/WSL. Wordlists are embedded; nothing to install alongside it.

## Techniques

| Group | What it fires |
|---|---|
| `header`  | IP-trust headers (`X-Forwarded-For`, `X-Real-IP`, `CF-Connecting-IP`, …), each with `127.0.0.1` **and** a real public IP |
| `rewrite` | `X-Original-URL` / `X-Rewrite-URL` / `X-Override-URL` pointing at the forbidden path |
| `verb`    | Verb tampering incl. WebDAV (`PROPFIND`, `MKCOL`, `COPY`, `MOVE`, `LOCK`) |
| `endpath` | Suffix tricks (`..;/`, `%2e`, `.json`, `%00`, `//`, trailing `/`, …) |
| `midpath` | Segment insertions (`/..;/admin`, `/%2e%2e/admin`, …) |
| `case`    | Path case-swap |

All lists are plain text under `wordlists/` and embedded at compile time — edit
them and rebuild to extend coverage.

## Build

```bash
cargo build --release
# binary: target/release/sidedoor
```

## Usage

```bash
sidedoor -u https://target.com/admin
sidedoor -u https://target.com/admin --json
sidedoor -l urls.txt -c 60 -x http://127.0.0.1:8080   # through Burp
sidedoor -u https://target.com/admin --wayback         # archive.org fallback if nothing bypasses
```

| Flag | Meaning |
|---|---|
| `-u, --url` | target URL |
| `-l, --list` | file of URLs, one per line |
| `-c, --concurrency` | max concurrent requests (default 40) |
| `--timeout` | per-request timeout ms (default 7000) |
| `--delay` | per-request delay ms — pace to avoid tripping WAFs (default 0) |
| `--retries` | retries on 429/503/transient error (default 3) |
| `--backoff-ms` | base backoff ms, doubles each retry (default 500) |
| `-x, --proxy` | proxy URL |
| `-r, --redirect` | follow redirects (default off, so a 30x is reported) |
| `--combine` | also fire header×path combinations |
| `--all-techniques` | disable stack-based pruning — fire every technique |
| `--ip` | public IP paired with 127.0.0.1 in spoof headers |
| `-H, --header` | extra header on every request (repeatable) |
| `-A, --user-agent` | custom UA |
| `--json` | JSON output |
| `--wayback` | query archive.org when nothing bypasses |
| `--min-score` | minimum score to report |

## Scope and honesty

This uses a standard HTTP client, so pure dot-segment payloads that the client
normalizes away (`/./`, `/../`) are intentionally **not** in the default lists —
only mutations that reach the wire intact are shipped. Raw-socket desync and
edge-vs-origin attribution are deliberately out of scope for this release; see
the tools credited below if you need them.

## Prior art

Built on techniques popularised by `nomore403`/`dontgo403`, `byp4xx`, `4-ZERO-3`,
`403jump`, and `bypass-403`. sidedoor's contribution is not new techniques — it's
calibration discipline and a dependable, portable single binary.

## License

MIT © Slybrick
