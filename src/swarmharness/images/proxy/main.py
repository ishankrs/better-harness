import os

from aiohttp import ClientSession, ClientTimeout, web


UPSTREAM = os.environ["UPSTREAM_BASE"].rstrip("/")
API_KEY = os.environ.get("LLM_API_KEY", "")
AUTH_MODE = os.environ.get("AUTH_MODE", "openai")
ALLOWED_PREFIXES = tuple(
    p.strip()
    for p in os.environ.get(
        "ALLOW_PATH_PREFIXES",
        "/v1/chat/completions,/v1/messages,/v1/completions,/v1/models,/v1/responses,/v1/embeddings",
    ).split(",")
    if p.strip()
)
ALLOWED_METHODS = {"GET", "POST"}
TIMEOUT = ClientTimeout(total=None, connect=30, sock_read=900)
HOP_HEADERS = {"connection", "keep-alive", "transfer-encoding", "upgrade", "proxy-authenticate", "proxy-authorization", "te", "trailers"}
STRIP_INBOUND = HOP_HEADERS | {"authorization", "x-api-key", "anthropic-version"}
DROP_RESPONSE_HEADERS = HOP_HEADERS | {"content-length", "content-encoding", "set-cookie", "server", "x-powered-by", "via"}


async def health(_: web.Request) -> web.Response:
    return web.Response(text="ok")


async def forward(request: web.Request) -> web.StreamResponse:
    if request.method not in ALLOWED_METHODS:
        return web.json_response({"error": {"message": f"method {request.method} not allowed", "type": "proxy_policy"}}, status=403)
    path = request.rel_url.path
    if not path.startswith(ALLOWED_PREFIXES):
        return web.json_response({"error": {"message": f"path {path} not allowed", "type": "proxy_policy"}}, status=403)

    target = UPSTREAM + request.rel_url.path_qs
    body = await request.read()
    headers = {
        k: v
        for k, v in request.headers.items()
        if k.lower() not in STRIP_INBOUND
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


async def init(app: web.Application) -> None:
    app["session"] = ClientSession(timeout=TIMEOUT)


async def cleanup(app: web.Application) -> None:
    await app["session"].close()


def main() -> None:
    app = web.Application(client_max_size=256 * 1024 * 1024)
    app.on_startup.append(init)
    app.on_cleanup.append(cleanup)
    app.router.add_get("/__health", health)
    app.router.add_route("*", "/{tail:.*}", forward)
    web.run_app(app, host="0.0.0.0", port=8080, access_log=None)


if __name__ == "__main__":
    main()
