import os
import secrets

from aiohttp import ClientSession, ClientTimeout, web
from yarl import URL


UPSTREAM = os.environ["UPSTREAM_BASE"].rstrip("/")
API_KEY = os.environ.get("LLM_API_KEY", "")
AUTH_MODE = os.environ.get("AUTH_MODE", "openai")
RUNNER_TOKEN = os.environ.get("RUNNER_TOKEN", "")
ALLOWED_PREFIXES = tuple(
    p.strip().rstrip("/") or "/"
    for p in os.environ.get(
        "ALLOW_PATH_PREFIXES",
        "/v1/chat/completions,/v1/messages,/v1/completions,/v1/models,/v1/responses,/v1/embeddings",
    ).split(",")
    if p.strip()
)
ALLOWED_METHODS = {"GET", "POST"}
MAX_BODY_BYTES = 16 * 1024 * 1024
TIMEOUT = ClientTimeout(total=1800, connect=30, sock_read=300)
HOP_HEADERS = {"connection", "keep-alive", "transfer-encoding", "upgrade", "proxy-authenticate", "proxy-authorization", "te", "trailers"}
STRIP_INBOUND = HOP_HEADERS | {
    "authorization",
    "x-api-key",
    "anthropic-version",
    "cookie",
    "forwarded",
    "x-forwarded-for",
    "x-forwarded-host",
    "x-forwarded-proto",
    "x-real-ip",
    "host",
    "content-length",
}
DROP_RESPONSE_HEADERS = HOP_HEADERS | {"content-length", "content-encoding", "set-cookie", "server", "x-powered-by", "via"}


async def health(_: web.Request) -> web.Response:
    return web.Response(text="ok")


def _path_allowed(norm_path: str) -> bool:
    for prefix in ALLOWED_PREFIXES:
        if prefix == "/":
            return True
        if norm_path == prefix or norm_path.startswith(prefix + "/"):
            return True
    return False


def _authorized(request: web.Request) -> bool:
    if not RUNNER_TOKEN:
        return True
    auth = request.headers.get("authorization", "")
    if auth.startswith("Bearer ") and secrets.compare_digest(auth[7:].strip(), RUNNER_TOKEN):
        return True
    key = request.headers.get("x-api-key", "")
    return bool(key) and secrets.compare_digest(key, RUNNER_TOKEN)


async def _read_bounded(request: web.Request) -> bytes:
    body = bytearray()
    while True:
        chunk = await request.content.readany()
        if not chunk:
            break
        body += chunk
        if len(body) > MAX_BODY_BYTES:
            raise web.HTTPRequestEntityTooLarge(max_size=MAX_BODY_BYTES, actual_size=len(body))
    return bytes(body)


async def forward(request: web.Request) -> web.StreamResponse:
    if request.method not in ALLOWED_METHODS:
        return web.json_response({"error": {"message": f"method {request.method} not allowed", "type": "proxy_policy"}}, status=403)
    if not _authorized(request):
        return web.json_response({"error": {"message": "missing or invalid runner token", "type": "proxy_auth"}}, status=401)
    target = UPSTREAM + request.rel_url.path_qs
    try:
        # Normalize the *request* path only: UPSTREAM may carry its own
        # sub-path (e.g. Azure deployments) which must not affect the allowlist.
        # yarl collapses %2E%2E/dot-segments here, closing the H-1 bypass.
        norm_path = URL("http://proxy" + request.rel_url.path_qs).path
    except ValueError:
        return web.json_response({"error": {"message": "malformed request target", "type": "proxy_policy"}}, status=400)
    if not _path_allowed(norm_path):
        return web.json_response({"error": {"message": f"path {norm_path} not allowed", "type": "proxy_policy"}}, status=403)

    nominated = {h.strip().lower() for h in request.headers.get("Connection", "").split(",") if h.strip()}
    body = await _read_bounded(request)
    headers = {
        k: v
        for k, v in request.headers.items()
        if k.lower() not in STRIP_INBOUND and k.lower() not in nominated
    }
    if AUTH_MODE == "anthropic":
        if API_KEY:
            headers["x-api-key"] = API_KEY
        headers["anthropic-version"] = request.headers.get("anthropic-version", "2023-06-01")
    else:
        if API_KEY:
            headers["Authorization"] = f"Bearer {API_KEY}"
    headers["Host"] = UPSTREAM.split("//", 1)[-1].split("/", 1)[0]
    try:
        session = request.app["session"]
        async with session.request(
            request.method, target, data=body, headers=headers, allow_redirects=False
        ) as upstream:
            resp_headers = {
                k: v
                for k, v in upstream.headers.items()
                if k.lower() not in DROP_RESPONSE_HEADERS
            }
            resp_headers["Server"] = "swarm-proxy"
            response = web.StreamResponse(status=upstream.status, headers=resp_headers)
            await response.prepare(request)
            async for chunk in upstream.content.iter_any():
                await response.write(chunk)
            await response.write_eof()
            return response
    except Exception as exc:
        return web.json_response({"error": {"message": f"proxy upstream failure: {exc}", "type": "proxy_error"}}, status=502)


async def session_ctx(app: web.Application):
    app["session"] = ClientSession(timeout=TIMEOUT)
    yield
    await app["session"].close()


def main() -> None:
    app = web.Application(client_max_size=MAX_BODY_BYTES)
    app.cleanup_ctx.append(session_ctx)
    app.router.add_get("/__health", health)
    app.router.add_route("*", "/{tail:.*}", forward)
    web.run_app(app, host="0.0.0.0", port=8080, access_log=None)


if __name__ == "__main__":
    main()
