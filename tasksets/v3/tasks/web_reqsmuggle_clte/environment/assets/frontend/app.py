import asyncio
import os

BE_HOST = os.environ.get("BE_HOST", "backend")
BE_PORT = int(os.environ.get("BE_PORT", "5000"))
HOST = "0.0.0.0"
PORT = 5000

_be_reader = None
_be_writer = None
_be_lock = asyncio.Lock()


async def get_backend():
    global _be_reader, _be_writer
    if _be_writer is None or _be_writer.is_closing():
        _be_reader, _be_writer = await asyncio.open_connection(BE_HOST, BE_PORT)
    return _be_reader, _be_writer


def parse_headers(buf: bytes):
    head = buf.split(b"\r\n\r\n", 1)[0]
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


async def read_one_response(reader: asyncio.StreamReader) -> bytes | None:
    try:
        head = await reader.readuntil(b"\r\n\r\n")
    except (asyncio.IncompleteReadError, ConnectionResetError, asyncio.LimitOverrunError):
        return None
    lines = head.split(b"\r\n")
    headers = []
    for line in lines[1:]:
        if b":" in line:
            k, _, v = line.partition(b":")
            headers.append((k.strip().lower(), v.strip()))
    cl = header_value(headers, b"content-length")
    body = b""
    if cl is not None:
        try:
            body = await reader.readexactly(int(cl))
        except asyncio.IncompleteReadError:
            pass
    return head + body


async def handle(client_reader: asyncio.StreamReader, client_writer: asyncio.StreamWriter) -> None:
    try:
        head = await client_reader.readuntil(b"\r\n\r\n")
    except (asyncio.IncompleteReadError, ConnectionResetError, asyncio.LimitOverrunError):
        client_writer.close()
        await client_writer.wait_closed()
        return
    _request_line, headers = parse_headers(head)
    # Path-based access control: block /flag
    parts = _request_line.split(b" ")
    path = parts[1] if len(parts) > 1 else b"/"
    if path == b"/flag":
        client_writer.write(
            b"HTTP/1.1 403 Forbidden\r\n"
            b"Content-Type: text/plain\r\n"
            b"Content-Length: 30\r\n"
            b"\r\nWAF: /flag is blocked\n"
        )
        await client_writer.drain()
        client_writer.close()
        await client_writer.wait_closed()
        return
    te = header_value(headers, b"transfer-encoding")
    cl = header_value(headers, b"content-length")
    # WAF: block any request where the FIRST Transfer-Encoding header
    # contains "chunked". This catches the obvious smuggling attempt.
    # (Bug: only the first TE header is checked, but the back-end may
    #  honor a second one.)
    if te is not None and b"chunked" in te.lower():
        client_writer.write(
            b"HTTP/1.1 403 Forbidden\r\n"
            b"Content-Type: text/plain\r\n"
            b"Content-Length: 20\r\n"
            b"\r\nWAF: TE blocked\n"
        )
        await client_writer.drain()
        client_writer.close()
        await client_writer.wait_closed()
        return
    # Frontend trusts Content-Length only (ignores Transfer-Encoding).
    body = b""
    if cl is not None:
        try:
            body = await client_reader.readexactly(int(cl))
        except asyncio.IncompleteReadError:
            pass
    raw_request = head + body
    async with _be_lock:
        be_reader, be_writer = await get_backend()
        be_writer.write(raw_request)
        await be_writer.drain()
        resp = await read_one_response(be_reader)
        if resp is None:
            client_writer.close()
            await client_writer.wait_closed()
            return
        client_writer.write(resp)
        await client_writer.drain()
    client_writer.close()
    await client_writer.wait_closed()


async def main() -> None:
    server = await asyncio.start_server(handle, HOST, PORT)
    print(f"frontend listening on {HOST}:{PORT} -> {BE_HOST}:{BE_PORT}", flush=True)
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
