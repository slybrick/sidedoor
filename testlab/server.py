import sys
import random
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# Loopback-only test lab for sb403. Mode via argv[1]:
#
# default    GET /admin->403; path with ';'->200; non-GET /admin->200; else 404
# wildcard   GET /admin->403; EVERYTHING else->200 (one identical page)
# java       like default, plus Set-Cookie: JSESSIONID (tool should KEEP ';' tricks)
# php        GET /admin->403; POST /admin->200; ';' paths->404 (no servlet params);
#            Set-Cookie: PHPSESSID (tool should PRUNE ';' tricks)
# throttle   ~40% of requests -> 429; otherwise default logic (tests backoff+warning)
# flap       GET /admin alternates 403/200 (tool must abort: nondeterministic)

MODE = sys.argv[1] if len(sys.argv) > 1 else "default"
WILDCARD_BODY = b"<html><body>generic landing page, same for every path</body></html>"

_lock = threading.Lock()
_flap = {"n": 0}


class H(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        sys.stderr.write("REQ %s %s\n" % (self.command, self.path))

    def _send(self, code, body, extra=None):
        self.send_response(code)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        if extra:
            for k, v in extra:
                self.send_header(k, v)
        self.end_headers()
        try:
            self.wfile.write(body)
        except Exception:
            pass

    def _respond(self):
        p = self.path

        if MODE == "throttle":
            if random.random() < 0.4:
                return self._send(429, b"slow down")
            return self._default()

        if MODE == "wildcard":
            if self.command == "GET" and p == "/admin":
                return self._send(403, b"Forbidden")
            return self._send(200, WILDCARD_BODY)

        if MODE == "flap":
            if self.command == "GET" and p == "/admin":
                with _lock:
                    _flap["n"] += 1
                    n = _flap["n"]
                if n % 2 == 1:
                    return self._send(403, b"Forbidden")
                return self._send(200, b"flapping open for no reason")
            return self._send(404, b"not found")

        if MODE == "java":
            return self._default(cookie=("Set-Cookie", "JSESSIONID=abc123; Path=/"))

        if MODE == "php":
            ck = ("Set-Cookie", "PHPSESSID=abc123; Path=/")
            if self.command != "GET" and p.startswith("/admin"):
                return self._send(200, b"UNLOCKED via verb tampering on php", [ck])
            if p == "/admin":
                return self._send(403, b"Forbidden", [ck])
            # php has no servlet path-params: ';' does NOT bypass
            return self._send(404, b"not found", [ck])

        return self._default()

    def _default(self, cookie=None):
        extra = [cookie] if cookie else None
        p = self.path
        if self.command != "GET" and p.startswith("/admin"):
            return self._send(200, b"UNLOCKED via verb tampering: secret admin contents go here", extra)
        if p == "/admin":
            return self._send(403, b"Forbidden", extra)
        if ";" in p:
            return self._send(200, b"UNLOCKED SECRET AREA: admin panel body, intentionally longer than the denial page", extra)
        return self._send(404, b"not found", extra)

    def do_GET(self):
        self._respond()

    def do_POST(self):
        self._respond()


if __name__ == "__main__":
    ThreadingHTTPServer(("127.0.0.1", 8777), H).serve_forever()
