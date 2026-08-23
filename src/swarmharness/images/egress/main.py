import asyncio
import ipaddress
import os
import socket

ALLOWED = [d.strip().lower() for d in os.environ.get("ALLOW_DOMAINS", "").split(",") if d.strip()]
DENY = b"HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n"
TUNNEL_PORT = 443

BLOCKED_NETS = [
    ipaddress.ip_network(n)
    for n in (
        "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
        "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.168.0.0/16",
        "198.18.0.0/15", "224.0.0.0/4", "240.0.0.0/4",
        "::1/128", "fc00::/7", "fe80::/10", "ff00::/8",
    )
]


def _is_public(ip_str: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    return not any(addr in net for net in BLOCKED_NETS)


def resolve_pinned(host: str) -> str | None:
    try:
        infos = socket.getaddrinfo(host, None, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM)
    except OSError:
        return None
    ips = [i[4][0] for i in infos]
    if not ips or not all(_is_public(ip) for ip in ips):
        return None
    return ips[0]


def allowed(host: str) -> bool:
    host = host.lower().strip(".")
    return any(host == d or host.endswith("." + d) for d in ALLOWED)


async def pipe(src: asyncio.StreamReader, dst: asyncio.StreamWriter) -> None:
    try:
        while True:
            chunk = await src.read(65536)
            if not chunk:
                break
            dst.write(chunk)
            await dst.drain()
    except Exception:
        pass
    finally:
        try:
            dst.close()
        except Exception:
            pass


async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        line = await asyncio.wait_for(reader.readline(), 30)
        parts = line.decode("latin1").split()
        if len(parts) >= 2 and parts[0].upper() == "CONNECT":
            while True:
                hdr = await asyncio.wait_for(reader.readline(), 30)
                if hdr in (b"\r\n", b"\n", b""):
                    break
            hostport = parts[1]
            host, _, port = hostport.rpartition(":")
            port = int(port) if port else 443
            if allowed(host) and port == TUNNEL_PORT:
                pinned = resolve_pinned(host)
                if pinned is not None:
                    try:
                        remote_reader, remote_writer = await asyncio.wait_for(
                            asyncio.open_connection(pinned, TUNNEL_PORT), 15
                        )
                        writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                        await writer.drain()
                        await asyncio.gather(
                            pipe(reader, remote_writer),
                            pipe(remote_reader, writer),
                        )
                        return
                    except Exception:
                        writer.write(b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n")
                        await writer.drain()
                        return
        writer.write(DENY)
        await writer.drain()
    except Exception:
        pass
    finally:
        try:
            writer.close()
        except Exception:
            pass


async def main() -> None:
    server = await asyncio.start_server(handle, "0.0.0.0", 3128)
    await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
