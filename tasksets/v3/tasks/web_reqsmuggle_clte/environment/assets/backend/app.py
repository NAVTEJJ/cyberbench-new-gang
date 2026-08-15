import asyncio
import os

FLAG = os.environ.get("FLAG", "cyberbench{REDACTED}")
HOST = "0.0.0.0"
PORT = 5000


def parse_headers(buf: bytes) -> tuple[bytes, list[tuple[bytes, bytes]]]:
    head, _, _rest = buf.partition(b"\r\n\r\n")
    lines = head.split(b"\r\n")
    request_line = lines[0]
    headers = []
    for line in lines[1:]:
        if b":" in line:
            k, _, v = line.partition(b":")
            headers.append((k.strip().lower(), v.strip()))
    return request_line, headers


def header_value(headers, name: bytes) -> bytes | None:
    name = name.lower()
    for k, v in headers:
        if k == name:
            return v
    return None


def build_response(status: bytes, body: bytes) -> bytes:
    return (
        b"HTTP/1.1 " + status + b"\r\n"
        b"Content-Type: text/plain\r\n"
        b"Content-Length: " + str(len(body)).encode() + b"\r\n"
        b"Connection: keep-alive\r\n"
        b"\r\n" + body
    )


def header_values(headers, name: bytes) -> list[bytes]:
    name = name.lower()
    return [v for k, v in headers if k == name]


async def read_request(reader: asyncio.StreamReader) -> tuple[bytes, list] | None:
    try:
        head = await reader.readuntil(b"\r\n\r\n")
    except (asyncio.IncompleteReadError, ConnectionResetError, asyncio.LimitOverrunError):
        return None
    request_line, headers = parse_headers(head)
    # Backend checks ALL Transfer-Encoding headers for "chunked".
    # If any TE header contains "chunked", the body is treated as chunked.
    te_values = header_values(headers, b"transfer-encoding")
    cl = header_value(headers, b"content-length")
    is_chunked = any(b"chunked" in v.lower() for v in te_values)
    body = b""
    if is_chunked:
        while True:
            try:
                size_line = await reader.readuntil(b"\r\n")
            except (asyncio.IncompleteReadError, ConnectionResetError):
                break
            try:
                size = int(size_line.strip().split(b";")[0], 16)
            except ValueError:
                break
            if size == 0:
                try:
                    await reader.readuntil(b"\r\n")
                except asyncio.IncompleteReadError:
                    pass
                break
            chunk = await reader.readexactly(size)
            await reader.readexactly(2)
            body += chunk
    elif cl is not None:
        try:
            body = await reader.readexactly(int(cl))
        except (asyncio.IncompleteReadError, ValueError):
            pass
    return request_line, headers, body, head


async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    while True:
        req = await read_request(reader)
        if req is None:
            break
        request_line, headers, body, head = req
        parts = request_line.split(b" ")
        path = parts[1] if len(parts) > 1 else b"/"
        if path == b"/flag":
            resp = build_response(b"200 OK", FLAG.encode() + b"\n")
        elif parts and parts[0] == b"POST":
            resp = build_response(b"200 OK", b"ok\n")
        else:
            resp = build_response(b"200 OK", b"hello\n")
        writer.write(resp)
        await writer.drain()
    writer.close()
    try:
        await writer.wait_closed()
    except Exception:
        pass


async def main() -> None:
    server = await asyncio.start_server(handle, HOST, PORT)
    print(f"backend listening on {HOST}:{PORT}", flush=True)
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
