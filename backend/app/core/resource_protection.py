"""Endpoint budgets and bounded request buffering; no sensitive request logging."""
import asyncio
import hashlib
import hmac

from starlette.requests import Request
from starlette.responses import JSONResponse

from app.core.config import settings
from app.core.security_store import BudgetExceeded, SecurityUnavailable


# Fixed windows start with the first admitted request. Counts include failures.
IP_POLICIES = {
    "register": (10, 3600), "login": (20, 60), "anonymous": (30, 3600),
    "scan": (60, 60), "feedback": (30, 60), "read": (120, 60), "mutation": (30, 60),
}


def request_group(method, path):
    if path == "/auth/register":
        return "register"
    if path == "/auth/login":
        return "login"
    if path.startswith("/auth/anonymous-session"):
        return "anonymous"
    if path in {"/auth/logout", "/auth/password"}:
        return "mutation"
    if path in {"/auth/me", "/auth/session"}:
        return "read"
    if path == "/scans" and method == "POST":
        return "scan"
    if path == "/scans" or path.startswith("/scans/"):
        if method == "GET":
            return "read"
        return "feedback" if path.endswith("/feedback") else "mutation"
    return None


def opaque_key(kind, identity):
    # Stable across workers, without putting raw addresses/identities into Redis keys.
    digest = hmac.new(settings.secret_key.get_secret_value().encode(),
                      (kind + ":" + identity).encode(), hashlib.sha256).hexdigest()
    return kind + ":" + digest


def actor_rules(group, actor, authenticated):
    rules = [(opaque_key("actor:" + group, actor), 60 if group == "read" else 20, 60)]
    if group == "scan":
        rules += [(opaque_key("scan-day", actor), 100 if authenticated else 30, 86400),
                  ("site-scan-day", 2000, 86400)]
    return rules


def check_login_budget(request, login):
    request.app.state.security_store.check([(opaque_key("login", login), 10, 60)])


def security_error(exc):
    if isinstance(exc, BudgetExceeded):
        return JSONResponse(status_code=429, content={"detail": "Request quota exceeded.",
                                                     "retry_after": exc.retry_after},
                            headers={"Retry-After": str(exc.retry_after), "Cache-Control": "no-store"})
    return JSONResponse(status_code=503, content={"detail": "Security service unavailable."},
                        headers={"Retry-After": "5", "Cache-Control": "no-store"})


def json_depth_allowed(body, maximum=64):
    depth = 0
    quoted = False
    escaped = False
    for value in body:
        if quoted:
            if escaped:
                escaped = False
            elif value == 92:
                escaped = True
            elif value == 34:
                quoted = False
        elif value == 34:
            quoted = True
        elif value in (91, 123):
            depth += 1
            if depth > maximum:
                return False
        elif value in (93, 125):
            depth -= 1
    return True


class ResourceProtectionMiddleware:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or scope["method"] == "OPTIONS":
            return await self.app(scope, receive, send)
        request = Request(scope)
        group = request_group(scope["method"], scope["path"])
        store = getattr(scope["app"].state, "security_store", None)
        lease = None
        try:
            if len(scope.get("raw_path", b"")) + len(scope.get("query_string", b"")) > 4096:
                return await JSONResponse({"detail": "Request target is too large."}, status_code=414)(scope, receive, send)
            if sum(len(k) + len(v) for k, v in scope.get("headers", [])) > 16384:
                return await JSONResponse({"detail": "Request headers are too large."}, status_code=431)(scope, receive, send)
            if group:
                if store is None:
                    raise SecurityUnavailable()
                # The ASGI peer is authoritative; never read forwarded/client-IP headers.
                peer = scope.get("client")
                identity = str(peer[0]) if peer else "unknown-peer"
                limit, seconds = IP_POLICIES[group]
                rules = [(opaque_key("ip:" + group, identity), limit, seconds)]
                if group == "scan":
                    rules.append((opaque_key("ip-scan-day", identity), 500, 86400))
                await asyncio.to_thread(store.check, rules)
                lease = await asyncio.to_thread(store.acquire, "requests", settings.max_inflight_requests)

            lengths = request.headers.getlist("content-length")
            if len(lengths) > 1 or (lengths and (not lengths[0].isascii() or not lengths[0].isdigit())):
                return await JSONResponse({"detail": "Invalid Content-Length."}, status_code=400)(scope, receive, send)
            if lengths and (len(lengths[0]) > 10 or int(lengths[0]) > settings.max_request_body_bytes):
                return await JSONResponse({"detail": "Request body is too large."}, status_code=413)(scope, receive, send)

            body = bytearray()
            deadline = asyncio.get_running_loop().time() + settings.request_body_timeout_seconds
            while True:
                remaining = deadline - asyncio.get_running_loop().time()
                if remaining <= 0:
                    return await JSONResponse({"detail": "Request body timed out."}, status_code=408)(scope, receive, send)
                try:
                    message = await asyncio.wait_for(receive(), remaining)
                except asyncio.TimeoutError:
                    return await JSONResponse({"detail": "Request body timed out."}, status_code=408)(scope, receive, send)
                if message["type"] == "http.disconnect":
                    return
                body.extend(message.get("body", b""))
                if len(body) > settings.max_request_body_bytes:
                    return await JSONResponse({"detail": "Request body is too large."}, status_code=413)(scope, receive, send)
                if not message.get("more_body", False):
                    break
            if "application/json" in request.headers.get("content-type", "").lower() and not json_depth_allowed(body):
                return await JSONResponse({"detail": "JSON nesting limit exceeded."}, status_code=413)(scope, receive, send)
            delivered = False

            async def replay():
                nonlocal delivered
                if not delivered:
                    delivered = True
                    return {"type": "http.request", "body": bytes(body), "more_body": False}
                return await receive()

            await self.app(scope, replay, send)
        except (BudgetExceeded, SecurityUnavailable) as exc:
            await security_error(exc)(scope, receive, send)
        finally:
            if lease:
                try:
                    await asyncio.to_thread(store.release, "requests", lease)
                except SecurityUnavailable:
                    # Response may already have been sent. The distributed lease expires.
                    pass
