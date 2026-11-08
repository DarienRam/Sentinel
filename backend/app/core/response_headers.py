"""Keep private API responses out of caches; do not log request contents."""
class PrivateResponseHeadersMiddleware:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        async def secured_send(message):
            if message["type"] == "http.response.start":
                headers = list(message.get("headers", []))
                if scope.get("path", "").startswith(("/auth/", "/scans")):
                    headers = [(k, v) for k, v in headers if k.lower() != b"cache-control"]
                    headers.append((b"cache-control", b"no-store"))
                headers.extend([(b"x-content-type-options", b"nosniff"), (b"referrer-policy", b"no-referrer")])
                message = {**message, "headers": headers}
            await send(message)
        await self.app(scope, receive, secured_send)
