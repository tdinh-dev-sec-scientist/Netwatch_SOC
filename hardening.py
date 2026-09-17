"""
HTTP hardening for NetWatch SOC: security headers, read-only demo mode and
request rate limiting.

Everything is configured from the environment so a hosting platform can turn
it on without code changes:

    NETWATCH_DEMO=1                  read-only, rate-limited public demo
    NETWATCH_RATE_LIMIT=600/60       per-client requests per window (0 = off)
    NETWATCH_GLOBAL_RATE_LIMIT=6000/60
                                     all clients combined (0 = off)
    NETWATCH_PROXY_HOPS=0            reverse proxies trusted for X-Forwarded-For

Rate limits default to off outside demo mode, so local development and the test
suite behave exactly as before. Security headers are always sent.

Limits of this design, stated rather than hidden:

  * Counters live in process memory. That is correct for the all-in-one
    topology (one gunicorn worker) but each worker of a multi-worker API would
    count separately. A shared store such as Redis would be needed there.
  * A per-client limit is only as good as the client address. With
    NETWATCH_PROXY_HOPS=0 the address is the TCP peer, which behind a platform
    proxy is the proxy itself, so every visitor shares one bucket. Raising the
    hop count trusts that many X-Forwarded-For entries; set it higher than the
    real number of proxies and clients can spoof their address. The global
    limit does not depend on addresses at all and is the backstop.
"""

import os
import threading
import time
from dataclasses import dataclass

from flask import jsonify, request
from werkzeug.middleware.proxy_fix import ProxyFix

SAFE_METHODS = frozenset({'GET', 'HEAD', 'OPTIONS'})

# Scripts load only from this origin and nothing inline runs: the dashboard's
# JavaScript lives in static/js/dashboard.js and binds its handlers with
# addEventListener, so an injected <script> or onclick attribute is refused by
# the browser rather than executed. Styles still need 'unsafe-inline' because
# the dashboard sets bar widths and colours through style attributes; that is a
# smaller exposure than script execution and is separate follow-up work.
# The policy also keeps fetch/XHR on this origin (so injected script could not
# send data elsewhere), and forbids plugins, <base> hijacking and framing.
CONTENT_SECURITY_POLICY = '; '.join((
    "default-src 'self'",
    "script-src 'self'",
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
    "font-src https://fonts.gstatic.com",
    "img-src 'self' data:",
    "connect-src 'self'",
    "object-src 'none'",
    "base-uri 'none'",
    "form-action 'none'",
    "frame-ancestors 'none'",
))

SECURITY_HEADERS = {
    'Content-Security-Policy': CONTENT_SECURITY_POLICY,
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Referrer-Policy': 'no-referrer',
    'Cross-Origin-Opener-Policy': 'same-origin',
    'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
}


def parse_limit(raw, name):
    """'600/60' -> (600, 60.0). '0' or '' -> None (limit disabled)."""
    if raw is None or raw.strip() in ('', '0'):
        return None
    try:
        count, _, window = raw.partition('/')
        count, window = int(count), float(window or 60)
    except ValueError:
        raise ValueError("%s must look like '600/60', got %r" % (name, raw))
    if count <= 0 or window <= 0:
        raise ValueError('%s must be positive, got %r' % (name, raw))
    return count, window


@dataclass(frozen=True)
class Settings:
    demo: bool = False
    client_limit: tuple = None      # (requests, window_s) or None
    global_limit: tuple = None
    proxy_hops: int = 0

    @classmethod
    def from_env(cls, env=None):
        env = os.environ if env is None else env
        demo = env.get('NETWATCH_DEMO', '0').lower() in ('1', 'true', 'yes')
        client_default = '600/60' if demo else '0'
        global_default = '6000/60' if demo else '0'
        try:
            hops = int(env.get('NETWATCH_PROXY_HOPS', '0'))
        except ValueError:
            raise ValueError('NETWATCH_PROXY_HOPS must be an integer, got %r'
                             % env.get('NETWATCH_PROXY_HOPS'))
        if hops < 0:
            raise ValueError('NETWATCH_PROXY_HOPS must not be negative')
        return cls(
            demo=demo,
            client_limit=parse_limit(
                env.get('NETWATCH_RATE_LIMIT', client_default),
                'NETWATCH_RATE_LIMIT'),
            global_limit=parse_limit(
                env.get('NETWATCH_GLOBAL_RATE_LIMIT', global_default),
                'NETWATCH_GLOBAL_RATE_LIMIT'),
            proxy_hops=hops,
        )


class RateLimiter:
    """Fixed-window request counter per key, bounded in memory.

    Fixed windows allow a burst of up to twice the limit across a window
    boundary. For protecting a small demo from being hammered that is an
    acceptable trade for O(1) memory per key and no background thread.
    """

    def __init__(self, limit, window_s, max_keys=10_000, clock=time.monotonic):
        self.limit = limit
        self.window_s = window_s
        self.max_keys = max_keys
        self._clock = clock
        self._lock = threading.Lock()
        self._windows = {}              # key -> [window_start, count]

    def hit(self, key):
        """Record one request. Returns (allowed, seconds_until_reset)."""
        now = self._clock()
        with self._lock:
            entry = self._windows.get(key)
            if entry is None or now - entry[0] >= self.window_s:
                if entry is None and len(self._windows) >= self.max_keys:
                    self._evict(now)
                entry = self._windows[key] = [now, 0]
            entry[1] += 1
            reset = max(0.0, self.window_s - (now - entry[0]))
            return entry[1] <= self.limit, reset

    def _evict(self, now):
        """Free room for a new key without forgetting every active client.

        Clearing the whole table would hand any client a way to reset the
        counter of every other one: fill it with fresh keys and all counts,
        including a hostile client's, go back to zero. So expired windows are
        dropped first, and only if that frees nothing does a bounded slice go.
        """
        expired = [k for k, (start, _c) in self._windows.items()
                   if now - start >= self.window_s]
        for key in expired:
            del self._windows[key]
        if len(self._windows) < self.max_keys:
            return
        # Every tracked key is still inside its window. Drop the oldest fifth,
        # by window start: those windows expire soonest, so they are the ones
        # whose counters were going to be reset anyway.
        oldest = sorted(self._windows, key=lambda key: self._windows[key][0])
        for key in oldest[:max(1, len(self._windows) // 5)]:
            del self._windows[key]

    def __len__(self):
        return len(self._windows)


def install(app, settings):
    """Attach headers, read-only enforcement and rate limits to a Flask app."""
    app.config['NETWATCH_DEMO'] = settings.demo
    app.config['NETWATCH_SECURITY'] = settings

    if settings.proxy_hops:
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=settings.proxy_hops)

    client_limiter = (RateLimiter(*settings.client_limit)
                      if settings.client_limit else None)
    global_limiter = (RateLimiter(*settings.global_limit)
                      if settings.global_limit else None)
    app.rate_limiters = {'client': client_limiter, 'global': global_limiter}

    def too_many(reset):
        response = jsonify({'error': 'rate limit exceeded, retry later',
                            'status': 429})
        response.status_code = 429
        response.headers['Retry-After'] = str(max(1, int(reset + 0.999)))
        return response

    @app.before_request
    def _enforce():
        if global_limiter is not None:
            allowed, reset = global_limiter.hit('*')
            if not allowed:
                return too_many(reset)
        if client_limiter is not None:
            allowed, reset = client_limiter.hit(request.remote_addr or '?')
            if not allowed:
                return too_many(reset)
        if settings.demo and request.method not in SAFE_METHODS:
            return jsonify({'error': 'this is a read-only demo; write '
                                     'operations are disabled',
                            'status': 403}), 403
        return None

    @app.after_request
    def _headers(response):
        for name, value in SECURITY_HEADERS.items():
            response.headers.setdefault(name, value)
        return response

    return app
