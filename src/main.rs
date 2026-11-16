// sidedoor — Slybrick 403/401 bypass scanner
//
// A deliberately small, reliable access-control-bypass tester. It does the
// proven core well: calibrate a baseline, fingerprint the stack, fire the
// research-grounded header / verb / path mutations, and only report a hit that
// measurably differs from both the baseline and a decoy (wildcard) response.
// Every hit prints the exact curl that reproduces it.
//
// Rename for release: change BRAND / BIN below (and the [[bin]] name in Cargo.toml).

use clap::Parser;
use futures::stream::{self, StreamExt};
use reqwest::header::{HeaderName, HeaderValue, LOCATION, USER_AGENT};
use reqwest::{Client, Method, Url};
use serde::Deserialize;
use std::collections::hash_map::DefaultHasher;
use std::hash::Hasher;
use std::io::IsTerminal;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

const BRAND: &str = "Slybrick";
const BIN: &str = "sidedoor"; // binary name
const VERSION: &str = env!("CARGO_PKG_VERSION");

// Rewrite headers always point at the forbidden path.
const REWRITE_HEADERS: &[&str] = &["X-Original-URL", "X-Rewrite-URL", "X-Override-URL"];

const WL_HEADERS: &str = include_str!("../wordlists/headers.txt");
const WL_VERBS: &str = include_str!("../wordlists/verbs.txt");
const WL_ENDPATHS: &str = include_str!("../wordlists/endpaths.txt");
const WL_MIDPATHS: &str = include_str!("../wordlists/midpaths.txt");

// Count of 429/503 throttle responses seen in the current run.
static THROTTLE: AtomicUsize = AtomicUsize::new(0);

#[derive(Parser, Debug)]
#[command(name = BIN, version, about = "Slybrick 403/401 access-control bypass scanner")]
struct Args {
    /// Target URL (e.g. https://host/admin)
    #[arg(short = 'u', long)]
    url: Option<String>,

    /// File of target URLs, one per line
    #[arg(short = 'l', long)]
    list: Option<String>,

    /// Positional target (alternative to -u)
    target: Option<String>,

    /// Max concurrent requests
    #[arg(short = 'c', long, default_value_t = 40)]
    concurrency: usize,

    /// Per-request timeout, milliseconds
    #[arg(long, default_value_t = 7000)]
    timeout: u64,

    /// Per-request delay per worker, milliseconds (pacing to avoid tripping WAFs)
    #[arg(long, default_value_t = 0)]
    delay: u64,

    /// Retries on a 429/503 or transient network error
    #[arg(long, default_value_t = 3)]
    retries: u32,

    /// Base backoff between retries, milliseconds (doubles each retry)
    #[arg(long, default_value_t = 500)]
    backoff_ms: u64,

    /// Proxy URL, e.g. http://127.0.0.1:8080
    #[arg(short = 'x', long)]
    proxy: Option<String>,

    /// Follow redirects (default: off, so a 30x is reported as a hit)
    #[arg(short = 'r', long)]
    redirect: bool,

    /// Public IP paired with 127.0.0.1 in spoof headers
    #[arg(long, default_value = "8.8.8.8")]
    ip: String,

    /// Also fire header x path combinations
    #[arg(long)]
    combine: bool,

    /// Fire every technique even if stack fingerprint says some can't apply
    #[arg(long)]
    all_techniques: bool,

    /// Extra header to add to every request: 'Name: value' (repeatable)
    #[arg(short = 'H', long = "header")]
    headers: Vec<String>,

    /// Custom User-Agent
    #[arg(short = 'A', long)]
    user_agent: Option<String>,

    /// Output results as JSON
    #[arg(long)]
    json: bool,

    /// If nothing bypasses, ask archive.org whether the path is cached
    #[arg(long)]
    wayback: bool,

    /// Minimum score to report (1 = report every scored hit)
    #[arg(long, default_value_t = 1)]
    min_score: i32,
}

#[derive(Clone)]
struct Probe {
    technique: &'static str,
    method: String,
    url: String,
    headers: Vec<(String, String)>,
    desc: String,
}

#[derive(Default, Clone)]
struct Res {
    status: u16,
    len: usize,
    hash: u64,
    location: Option<String>,
    server: String,
    powered: String,
    cookies: String,
    ok: bool,
}

struct Palette {
    reset: &'static str,
    green: &'static str,
    yellow: &'static str,
    cyan: &'static str,
    gray: &'static str,
    bold: &'static str,
    red: &'static str,
}

impl Palette {
    fn new(color: bool) -> Self {
        if color {
            Palette {
                reset: "\x1b[0m",
                green: "\x1b[32m",
                yellow: "\x1b[33m",
                cyan: "\x1b[36m",
                gray: "\x1b[90m",
                bold: "\x1b[1m",
                red: "\x1b[31m",
            }
        } else {
            Palette {
                reset: "",
                green: "",
                yellow: "",
                cyan: "",
                gray: "",
                bold: "",
                red: "",
            }
        }
    }
}

fn lines(raw: &str) -> Vec<String> {
    raw.lines()
        .map(|l| l.trim_end_matches(['\r', '\n']))
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| l.to_string())
        .collect()
}

fn abs_diff(a: usize, b: usize) -> usize {
    if a > b {
        a - b
    } else {
        b - a
    }
}

fn split_last(path: &str) -> (String, String) {
    let p = path.trim_end_matches('/');
    match p.rfind('/') {
        Some(i) => (p[..=i].to_string(), p[i + 1..].to_string()),
        None => ("/".to_string(), p.to_string()),
    }
}

/// Fingerprint the backend from baseline response headers.
/// Returns (human label, whether to prune servlet-only `;` path tricks).
fn fingerprint(r: &Res) -> (String, bool) {
    let s = r.server.to_lowercase();
    let pw = r.powered.to_lowercase();
    let ck = r.cookies.to_uppercase();

    if ck.contains("JSESSIONID")
        || s.contains("tomcat")
        || s.contains("jetty")
        || pw.contains("servlet")
        || pw.contains("jsp")
    {
        return ("Java/servlet".into(), false); // `;` tricks are native here — keep
    }
    if ck.contains("PHPSESSID") || pw.contains("php") || s.contains("php") {
        return ("PHP".into(), true); // no servlet path-params — prune `;`
    }
    if ck.contains("CONNECT.SID") || pw.contains("express") {
        return ("Node/Express".into(), true); // prune `;`
    }
    if ck.contains("ASP.NET") || pw.contains("asp.net") || s.contains("iis") || s.contains("microsoft") {
        return ("IIS/ASP.NET".into(), false); // .NET has its own `;` quirks — keep
    }

    let label = if s.contains("nginx") {
        "nginx (proxy?)"
    } else if s.contains("apache") {
        "apache"
    } else if s.contains("cloudflare") {
        "cloudflare edge"
    } else if !s.is_empty() {
        "other"
    } else {
        "unknown"
    };
    (label.to_string(), false) // unknown → keep everything (conservative)
}

async fn fetch(client: &Client, args: &Args, p: &Probe) -> Res {
    let method = Method::from_bytes(p.method.as_bytes()).unwrap_or(Method::GET);
    let ua = args
        .user_agent
        .clone()
        .unwrap_or_else(|| format!("{}/{}", BIN, VERSION));

    let mut attempt: u32 = 0;
    loop {
        if args.delay > 0 {
            tokio::time::sleep(Duration::from_millis(args.delay)).await;
        }

        let mut req = client
            .request(method.clone(), &p.url)
            .header(USER_AGENT, ua.clone());
        for (k, v) in &p.headers {
            if let (Ok(name), Ok(val)) =
                (HeaderName::from_bytes(k.as_bytes()), HeaderValue::from_str(v))
            {
                req = req.header(name, val);
            }
        }
        for h in &args.headers {
            if let Some((k, v)) = h.split_once(':') {
                if let (Ok(name), Ok(val)) = (
                    HeaderName::from_bytes(k.trim().as_bytes()),
                    HeaderValue::from_str(v.trim()),
                ) {
                    req = req.header(name, val);
                }
            }
        }

        match req.send().await {
            Ok(resp) => {
                let status = resp.status().as_u16();
                if status == 429 || status == 503 {
                    THROTTLE.fetch_add(1, Ordering::Relaxed);
                    if attempt < args.retries {
                        let shift = attempt.min(5);
                        let wait = args.backoff_ms.saturating_mul(1u64 << shift);
                        tokio::time::sleep(Duration::from_millis(wait)).await;
                        attempt += 1;
                        continue;
                    }
                }
                let location = resp
                    .headers()
                    .get(LOCATION)
                    .and_then(|v| v.to_str().ok())
                    .map(|s| s.to_string());
                let server = resp
                    .headers()
                    .get("server")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("")
                    .to_string();
                let powered = resp
                    .headers()
                    .get("x-powered-by")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("")
                    .to_string();
                let cookies = resp
                    .headers()
                    .get_all("set-cookie")
                    .iter()
                    .filter_map(|v| v.to_str().ok())
                    .map(|s| s.split('=').next().unwrap_or("").trim().to_string())
                    .collect::<Vec<_>>()
                    .join(",");
                let body = resp.bytes().await.unwrap_or_default();
                let mut h = DefaultHasher::new();
                h.write(&body);
                return Res {
                    status,
                    len: body.len(),
                    hash: h.finish(),
                    location,
                    server,
                    powered,
                    cookies,
                    ok: true,
                };
            }
            Err(_) if attempt < args.retries => {
                tokio::time::sleep(Duration::from_millis(150)).await;
                attempt += 1;
                continue;
            }
            Err(_) => return Res::default(),
        }
    }
}

fn gen_probes(args: &Args, target: &str, prune_semicolon: bool) -> Result<Vec<Probe>, String> {
    let u = Url::parse(target).map_err(|e| format!("bad URL: {e}"))?;
    let scheme = u.scheme();
    let host = u.host_str().ok_or("URL has no host")?;
    let base = match u.port() {
        Some(port) => format!("{scheme}://{host}:{port}"),
        None => format!("{scheme}://{host}"),
    };
    let path = {
        let p = u.path();
        if p.is_empty() {
            "/".to_string()
        } else {
            p.to_string()
        }
    };

    let prune = prune_semicolon && !args.all_techniques;
    let drop_tok = |t: &str| prune && t.contains(';');

    let mut probes: Vec<Probe> = Vec::new();

    // 1) IP-spoof headers — each tried with 127.0.0.1 and a real public IP.
    let hdr_list = lines(WL_HEADERS);
    for h in &hdr_list {
        for ip in ["127.0.0.1", args.ip.as_str()] {
            probes.push(Probe {
                technique: "header",
                method: "GET".into(),
                url: target.to_string(),
                headers: vec![(h.clone(), ip.to_string())],
                desc: format!("{h}: {ip}"),
            });
        }
    }

    // 2) URL-rewrite headers — request base, smuggle the path in a header.
    for h in REWRITE_HEADERS {
        probes.push(Probe {
            technique: "rewrite",
            method: "GET".into(),
            url: format!("{base}/"),
            headers: vec![(h.to_string(), path.clone())],
            desc: format!("{h}: {path}"),
        });
    }

    // 3) Verb tampering.
    for v in lines(WL_VERBS) {
        probes.push(Probe {
            technique: "verb",
            method: v.clone(),
            url: target.to_string(),
            headers: vec![],
            desc: format!("method {v}"),
        });
    }

    // 4) End-path suffixes.
    let end_list = lines(WL_ENDPATHS);
    for e in &end_list {
        if drop_tok(e) {
            continue;
        }
        probes.push(Probe {
            technique: "endpath",
            method: "GET".into(),
            url: format!("{target}{e}"),
            headers: vec![],
            desc: format!("{path}{e}"),
        });
    }

    // 5) Mid-path insertions (before the last segment).
    let (dir, last) = split_last(&path);
    for m in lines(WL_MIDPATHS) {
        if drop_tok(&m) {
            continue;
        }
        let np = format!("{dir}{m}{last}");
        probes.push(Probe {
            technique: "midpath",
            method: "GET".into(),
            url: format!("{base}{np}"),
            headers: vec![],
            desc: np,
        });
    }

    // 6) Case swap.
    let up = path.to_uppercase();
    if up != path {
        probes.push(Probe {
            technique: "case",
            method: "GET".into(),
            url: format!("{base}{up}"),
            headers: vec![],
            desc: up,
        });
    }

    // 7) Combined header x path (opt-in) — some bypasses need both at once.
    if args.combine {
        let combo_headers = ["X-Forwarded-For", "X-Original-URL", "X-Real-IP", "X-Forwarded-Host"];
        let mut combo_ends: Vec<&str> = vec!["/", "%2e", "..%2f", "%252e"];
        combo_ends.retain(|e| !(prune && e.contains(';')));
        for h in combo_headers {
            for e in &combo_ends {
                probes.push(Probe {
                    technique: "combo",
                    method: "GET".into(),
                    url: format!("{target}{e}"),
                    headers: vec![(h.to_string(), "127.0.0.1".to_string())],
                    desc: format!("{h}:127.0.0.1 + {path}{e}"),
                });
            }
        }
    }

    Ok(probes)
}

fn len_bonus(a: usize, b: usize) -> i32 {
    let d = abs_diff(a, b);
    if d > 2000 {
        8
    } else if d > 200 {
        5
    } else if d > 0 {
        2
    } else {
        0
    }
}

/// Score a probe result against the calibrated baseline and decoy.
/// Returns (score, reason). Score 0 = not a hit.
fn score(base: &Res, decoy: &Res, root: &Res, catch_all: bool, tol: usize, r: &Res) -> (i32, String) {
    if !r.ok {
        return (0, String::new());
    }
    // Never treat a throttle response as a bypass.
    if r.status == 429 || r.status == 503 {
        return (0, String::new());
    }

    // Strongest signal: a denial turned into a success/redirect.
    if r.status < 400 && r.status != base.status {
        // Reaching the public root/home page is NOT a bypass of the protected
        // path — kills rewrite-header probes that just fetch `/`, and path
        // tricks that resolve back to the site root.
        if root.ok && r.status == root.status && r.hash == root.hash {
            return (0, String::new());
        }
        // On a wildcard host, the generic decoy page is not a bypass.
        if catch_all
            && r.status == decoy.status
            && abs_diff(r.len, decoy.len) <= tol
            && r.hash == decoy.hash
        {
            return (0, String::new());
        }
        let base_score = if r.status < 300 { 90 } else { 50 };
        let mut reason = format!("{} (was {})", r.status, base.status);
        if r.status >= 300 {
            if let Some(loc) = &r.location {
                reason.push_str(&format!(" -> {loc}"));
            }
        }
        return (base_score + len_bonus(base.len, r.len), reason);
    }

    // Weaker signal: same status, but the body moved beyond measured jitter.
    // An empty body (e.g. a HEAD response) never counts as "content changed".
    if r.status == base.status && r.len > 0 && r.hash != base.hash && abs_diff(r.len, base.len) > tol {
        let s = (20 + len_bonus(base.len, r.len)).min(40);
        return (
            s,
            format!("same {}, body {}b vs {}b", r.status, r.len, base.len),
        );
    }

    (0, String::new())
}

fn curl_for(args: &Args, p: &Probe) -> String {
    let mut s = String::from("curl -sk");
    if p.method != "GET" {
        s.push_str(&format!(" -X {}", p.method));
    }
    for (k, v) in &p.headers {
        s.push_str(&format!(" -H '{}: {}'", k, v));
    }
    for h in &args.headers {
        s.push_str(&format!(" -H '{}'", h));
    }
    s.push_str(&format!(" '{}'", p.url));
    s
}

async fn plain_get(client: &Client, args: &Args, url: &str) -> Res {
    fetch(
        client,
        args,
        &Probe {
            technique: "calibrate",
            method: "GET".into(),
            url: url.to_string(),
            headers: vec![],
            desc: String::new(),
        },
    )
    .await
}

fn rand_token(n: usize) -> String {
    let mut x = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0x9e3779b97f4a7c15);
    let alpha = b"abcdefghijklmnopqrstuvwxyz0123456789";
    let mut out = String::with_capacity(n);
    for _ in 0..n {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        out.push(alpha[(x as usize) % alpha.len()] as char);
    }
    out
}

#[derive(Deserialize)]
struct Wb {
    archived_snapshots: Option<Snap>,
}
#[derive(Deserialize)]
struct Snap {
    closest: Option<Closest>,
}
#[derive(Deserialize)]
struct Closest {
    available: bool,
    url: Option<String>,
}

async fn wayback(client: &Client, target: &str) -> Option<String> {
    let api = format!(
        "https://archive.org/wayback/available?url={}",
        urlencode(target)
    );
    let resp = client.get(&api).send().await.ok()?;
    let wb: Wb = resp.json().await.ok()?;
    let c = wb.archived_snapshots?.closest?;
    if c.available {
        c.url
    } else {
        None
    }
}

fn urlencode(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{:02X}", b)),
        }
    }
    out
}

async fn run_target(client: &Client, args: &Arc<Args>, pal: &Palette, target: &str) {
    eprintln!("{}[*]{} {}", pal.cyan, pal.reset, target);
    let throttle_before = THROTTLE.load(Ordering::Relaxed);

    // Calibrate: fire the baseline twice to measure jitter, plus a decoy path.
    let base1 = plain_get(client, args, target).await;
    if !base1.ok {
        eprintln!("  {}[!]{} baseline request failed", pal.red, pal.reset);
        return;
    }
    if base1.status == 429 || base1.status == 503 {
        eprintln!(
            "  {}[!]{} baseline is throttled ({}) — cannot calibrate; lower -c or raise --delay and re-run",
            pal.red, pal.reset, base1.status
        );
        return;
    }
    let base2 = plain_get(client, args, target).await;

    // Nondeterminism guard: a flapping baseline voids every comparison.
    if base2.ok && base2.status != base1.status {
        eprintln!(
            "  {}[!]{} baseline is nondeterministic (status {} then {}) — comparisons are void, skipping",
            pal.red, pal.reset, base1.status, base2.status
        );
        return;
    }

    let jitter = if base2.ok {
        abs_diff(base1.len, base2.len)
    } else {
        0
    };
    let tol = std::cmp::max(48, jitter.saturating_mul(3));

    let (stack, prune) = fingerprint(&base1);

    let decoy_url = {
        let sep = if target.ends_with('/') { "" } else { "/" };
        format!("{target}{sep}{}", rand_token(14))
    };
    let decoy = plain_get(client, args, &decoy_url).await;
    let catch_all = decoy.ok && decoy.status < 400;

    // Root/home control: a "bypass" that just returns the public site root is
    // not a bypass of the protected path.
    let root_url = match Url::parse(target) {
        Ok(u) => {
            let scheme = u.scheme();
            let host = u.host_str().unwrap_or("");
            match u.port() {
                Some(p) => format!("{scheme}://{host}:{p}/"),
                None => format!("{scheme}://{host}/"),
            }
        }
        Err(_) => target.to_string(),
    };
    let root = plain_get(client, args, &root_url).await;

    eprintln!(
        "  baseline {} ({}b), jitter {}b, tol {}b, stack {}{}",
        base1.status,
        base1.len,
        jitter,
        tol,
        stack,
        if prune && !args.all_techniques {
            " (pruning ; tricks)"
        } else {
            ""
        }
    );
    if base1.status < 400 {
        eprintln!(
            "  {}[!]{} baseline is not a denial ({}) — nothing to bypass here",
            pal.yellow, pal.reset, base1.status
        );
        return;
    }
    if jitter > 4096 {
        eprintln!(
            "  {}[!]{} baseline body is unstable (jitter {}b) — body-diff hits are unreliable",
            pal.yellow, pal.reset, jitter
        );
    }
    if catch_all {
        eprintln!(
            "  {}[!]{} host answers a random path with {} — likely wildcard; hits are filtered against it",
            pal.yellow, pal.reset, decoy.status
        );
    }

    let probes = match gen_probes(args, target, prune) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("  {}[!]{} {}", pal.red, pal.reset, e);
            return;
        }
    };
    let total = probes.len();

    let conc = args.concurrency.max(1);
    let results: Vec<(Probe, Res)> = stream::iter(probes.into_iter())
        .map(|p| {
            let client = client.clone();
            let args = Arc::clone(args);
            async move {
                let r = fetch(&client, args.as_ref(), &p).await;
                (p, r)
            }
        })
        .buffer_unordered(conc)
        .collect()
        .await;

    let mut hits: Vec<(Probe, Res, i32, String)> = Vec::new();
    for (p, r) in results {
        let (s, reason) = score(&base1, &decoy, &root, catch_all, tol, &r);
        if s >= args.min_score && s > 0 {
            hits.push((p, r, s, reason));
        }
    }
    hits.sort_by(|a, b| b.2.cmp(&a.2));

    if args.json {
        let arr: Vec<serde_json::Value> = hits
            .iter()
            .map(|(p, r, s, reason)| {
                serde_json::json!({
                    "target": target,
                    "stack": stack,
                    "technique": p.technique,
                    "method": p.method,
                    "url": p.url,
                    "mutation": p.desc,
                    "status": r.status,
                    "length": r.len,
                    "score": s,
                    "reason": reason,
                    "curl": curl_for(args, p),
                })
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&arr).unwrap_or_default());
    } else {
        for (p, _r, s, reason) in &hits {
            println!(
                "{}[HIT +{}]{} {:<8} {}{}{}  -> {}",
                pal.green, s, pal.reset, p.technique, pal.bold, p.desc, pal.reset, reason
            );
            println!("    {}{}{}", pal.gray, curl_for(args, p), pal.reset);
        }
    }

    let throttled = THROTTLE.load(Ordering::Relaxed) - throttle_before;
    eprintln!(
        "  {} probes, {}{} hits{}{}",
        total,
        pal.green,
        hits.len(),
        pal.reset,
        if throttled > 0 {
            format!(", {} throttled", throttled)
        } else {
            String::new()
        }
    );
    if total > 0 && throttled * 5 > total {
        eprintln!(
            "  {}[!]{} heavy throttling ({}/{}) — the baseline and results are suspect; lower -c or raise --delay and re-run",
            pal.yellow, pal.reset, throttled, total
        );
    }

    if hits.is_empty() && args.wayback {
        if let Some(u) = wayback(client, target).await {
            eprintln!(
                "  {}[wayback]{} blocked live, but an archived copy exists: {}",
                pal.yellow, pal.reset, u
            );
        }
    }
}

fn banner(pal: &Palette) {
    eprintln!(
        "{}{} · {}{} {}(403/401 bypass){}",
        pal.bold, BRAND, BIN, pal.reset, pal.gray, pal.reset
    );
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let color = std::io::stdout().is_terminal();
    let pal = Palette::new(color);
    banner(&pal);

    let mut targets: Vec<String> = Vec::new();
    if let Some(u) = &args.url {
        targets.push(u.clone());
    }
    if let Some(t) = &args.target {
        targets.push(t.clone());
    }
    if let Some(lf) = &args.list {
        let content = std::fs::read_to_string(lf)?;
        for line in content.lines() {
            let t = line.trim();
            if !t.is_empty() && !t.starts_with('#') {
                targets.push(t.to_string());
            }
        }
    }
    if targets.is_empty() {
        eprintln!("no target: use -u <url>, a positional URL, or -l <file>");
        std::process::exit(2);
    }

    let mut cb = Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(Duration::from_millis(args.timeout))
        .redirect(if args.redirect {
            reqwest::redirect::Policy::limited(5)
        } else {
            reqwest::redirect::Policy::none()
        });
    if let Some(p) = &args.proxy {
        cb = cb.proxy(reqwest::Proxy::all(p)?);
    }
    let client = cb.build()?;

    let args = Arc::new(args);
    for t in targets {
        let t = if t.starts_with("http://") || t.starts_with("https://") {
            t
        } else {
            format!("https://{t}")
        };
        run_target(&client, &args, &pal, &t).await;
    }

    Ok(())
}
