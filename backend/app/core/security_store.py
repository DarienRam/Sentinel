"""Bounded local security state; optional atomic Redis state for production.

No database rows, scan bodies, passwords or raw IPs are stored here. Redis is
required in production and must use a dedicated, access-controlled deployment.
"""
from dataclasses import asdict, dataclass
import hashlib
import json
import math
import secrets
import threading
import time
from urllib.parse import urlsplit


class SecurityUnavailable(Exception):
    pass


class BudgetExceeded(Exception):
    def __init__(self, retry_after: int):
        self.retry_after = max(1, retry_after)


@dataclass(frozen=True)
class AnonymousSession:
    owner: str
    csrf: str
    expires_at: float


@dataclass(frozen=True)
class AccountSession:
    user_id: int
    csrf: str
    credential_version: str
    expires_at: float


def credential_key(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


class MemorySecurityStore:
    """Single-process development/tests only; all read/decide/write is locked."""
    def __init__(self, clock=time.time, max_entries=10000):
        self.clock = clock
        self.max_entries = max_entries
        self.lock = threading.RLock()
        self.counters = {}
        self.sessions = {}
        self.account_sessions = {}
        self.leases = {}

    def _prune(self):
        now = self.clock()
        self.counters = {k: v for k, v in self.counters.items() if v[1] > now}
        self.sessions = {k: v for k, v in self.sessions.items() if v.expires_at > now}
        self.account_sessions = {k: v for k, v in self.account_sessions.items() if v.expires_at > now}
        self.leases = {k: {t: end for t, end in v.items() if end > now}
                       for k, v in self.leases.items() if any(end > now for end in v.values())}

    def check(self, rules):
        with self.lock:
            self._prune()
            now = self.clock()
            retry = max((math.ceil(self.counters[k][1] - now) for k, limit, _ in rules
                         if k in self.counters and self.counters[k][0] >= limit), default=0)
            if retry:
                raise BudgetExceeded(retry)
            if len(self.counters) + sum(k not in self.counters for k, _, _ in rules) > self.max_entries:
                raise SecurityUnavailable()
            for key, _, window in rules:
                count, end = self.counters.get(key, (0, now + window))
                self.counters[key] = (count + 1, end)

    def acquire(self, key, limit, seconds=60):
        with self.lock:
            self._prune()
            active = self.leases.setdefault(key, {})
            if len(active) >= limit:
                raise BudgetExceeded(1)
            token = secrets.token_urlsafe(24)
            active[token] = self.clock() + seconds
            return token

    def release(self, key, token):
        with self.lock:
            self.leases.get(key, {}).pop(token, None)

    def load_session(self, key):
        with self.lock:
            session = self.sessions.get(key)
            if session and session.expires_at > self.clock():
                return session
            self.sessions.pop(key, None)
            return None

    def put_session(self, key, session):
        with self.lock:
            self._prune()
            if len(self.sessions) >= self.max_entries or key in self.sessions:
                raise SecurityUnavailable()
            self.sessions[key] = session

    def rotate_session(self, old, new, session):
        with self.lock:
            if not self.load_session(old) or new in self.sessions:
                return False
            self.sessions[new] = session
            del self.sessions[old]
            return True

    def revoke_session(self, key):
        with self.lock:
            self.sessions.pop(key, None)

    def load_account_session(self, key):
        with self.lock:
            session = self.account_sessions.get(key)
            if session and session.expires_at > self.clock():
                return session
            self.account_sessions.pop(key, None)
            return None

    def put_account_session(self, key, session):
        with self.lock:
            self._prune()
            if len(self.account_sessions) >= self.max_entries or key in self.account_sessions:
                raise SecurityUnavailable()
            self.account_sessions[key] = session

    def revoke_account_session(self, key):
        with self.lock:
            self.account_sessions.pop(key, None)

    def close(self):
        pass


# A single script admits all applicable windows or none of them.
RATE_SCRIPT = """
local retry = 0
for i,key in ipairs(KEYS) do
  local count = tonumber(redis.call('GET',key) or '0')
  if count >= tonumber(ARGV[2*i-1]) then
    retry = math.max(retry,redis.call('TTL',key),1)
  end
end
if retry > 0 then return retry end
for i,key in ipairs(KEYS) do
  if redis.call('INCR',key) == 1 then redis.call('EXPIRE',key,ARGV[2*i]) end
end
return 0
"""
LEASE_SCRIPT = """
local t = redis.call('TIME')
local now = tonumber(t[1])*1000 + math.floor(tonumber(t[2])/1000)
redis.call('ZREMRANGEBYSCORE',KEYS[1],'-inf',now)
if redis.call('ZCARD',KEYS[1]) >= tonumber(ARGV[1]) then return 0 end
redis.call('ZADD',KEYS[1],now+tonumber(ARGV[3])*1000,ARGV[2])
redis.call('EXPIRE',KEYS[1],tonumber(ARGV[3])+1)
return 1
"""
ROTATE_SCRIPT = """
local original = redis.call('GET',KEYS[1])
local ttl = redis.call('PTTL',KEYS[1])
if not original or ttl <= 0 then return 0 end
if not redis.call('SET',KEYS[2],ARGV[1],'PX',ttl,'NX') then return 0 end
redis.call('DEL',KEYS[1])
return 1
"""


class RedisSecurityStore:
    # The hash tag keeps multi-key Lua operations in one Redis Cluster slot.
    prefix = "sentinel:{security}:"

    def __init__(self, url=None, client=None):
        try:
            if client is None:
                import redis
                client = redis.Redis.from_url(url, socket_connect_timeout=0.5,
                                              socket_timeout=0.5, max_connections=16,
                                              decode_responses=True)
            self.client = client
            self.client.ping()
        except Exception:
            raise SecurityUnavailable() from None

    def _call(self, method, *args, **kwargs):
        try:
            return getattr(self.client, method)(*args, **kwargs)
        except Exception:
            raise SecurityUnavailable() from None

    def check(self, rules):
        keys = [self.prefix + "rate:" + k for k, _, _ in rules]
        arguments = [value for _, limit, window in rules for value in (limit, window)]
        retry = int(self._call("eval", RATE_SCRIPT, len(keys), *keys, *arguments))
        if retry:
            raise BudgetExceeded(retry)

    def acquire(self, key, limit, seconds=60):
        token = secrets.token_urlsafe(24)
        if not self._call("eval", LEASE_SCRIPT, 1, self.prefix + "lease:" + key, limit, token, seconds):
            raise BudgetExceeded(1)
        return token

    def release(self, key, token):
        self._call("zrem", self.prefix + "lease:" + key, token)

    def load_session(self, key):
        raw = self._call("get", self.prefix + "session:" + key)
        if raw is None:
            return None
        try:
            session = AnonymousSession(**json.loads(raw))
            return session if session.expires_at > time.time() else None
        except (TypeError, ValueError):
            raise SecurityUnavailable() from None

    def put_session(self, key, session):
        ttl = max(1, math.ceil(session.expires_at - time.time()))
        if not self._call("set", self.prefix + "session:" + key, json.dumps(asdict(session)), ex=ttl, nx=True):
            raise SecurityUnavailable()

    def rotate_session(self, old, new, session):
        return bool(self._call("eval", ROTATE_SCRIPT, 2, self.prefix + "session:" + old,
                               self.prefix + "session:" + new, json.dumps(asdict(session))))

    def revoke_session(self, key):
        self._call("delete", self.prefix + "session:" + key)

    def load_account_session(self, key):
        raw = self._call("get", self.prefix + "account:" + key)
        if raw is None:
            return None
        try:
            session = AccountSession(**json.loads(raw))
            return session if session.expires_at > time.time() else None
        except (TypeError, ValueError):
            raise SecurityUnavailable() from None

    def put_account_session(self, key, session):
        ttl = max(1, math.ceil(session.expires_at - time.time()))
        if not self._call("set", self.prefix + "account:" + key, json.dumps(asdict(session)), ex=ttl, nx=True):
            raise SecurityUnavailable()

    def revoke_account_session(self, key):
        self._call("delete", self.prefix + "account:" + key)

    def close(self):
        self._call("close")


def _production_origin_allowed(origin):
    try:
        parsed = urlsplit(origin)
        _ = parsed.port
        return (parsed.scheme == "https" and bool(parsed.hostname) and "*" not in origin
                and not any(c.isspace() for c in origin) and not parsed.path
                and not parsed.query and not parsed.fragment and parsed.username is None)
    except ValueError:
        return False


def create_security_store(settings):
    if settings.app_env == "production":
        if settings.security_backend != "redis" or not settings.redis_url:
            raise RuntimeError("Production requires the Redis security backend; memory fallback is disabled.")
        if not settings.frontend_origins or any(
            not _production_origin_allowed(origin) for origin in settings.frontend_origins
        ):
            raise RuntimeError("Production requires explicit HTTPS frontend origins.")
    if settings.security_backend == "redis":
        if not settings.redis_url:
            raise RuntimeError("REDIS_URL is required for the Redis security backend.")
        try:
            return RedisSecurityStore(settings.redis_url.get_secret_value())
        except SecurityUnavailable:
            raise RuntimeError("Security infrastructure unavailable; refusing startup.") from None
    return MemorySecurityStore()
