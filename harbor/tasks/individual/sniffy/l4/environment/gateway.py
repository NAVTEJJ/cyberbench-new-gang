from __future__ import annotations

import asyncio
import json
import os
import sys


async def pipe(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        while chunk := await reader.read(65536):
            writer.write(chunk)
            await writer.drain()
    finally:
        writer.close()
        await writer.wait_closed()


async def handle_client(
    client_reader: asyncio.StreamReader,
    client_writer: asyncio.StreamWriter,
    upstream_host: str,
    upstream_port: int,
) -> None:
    try:
        upstream_reader, upstream_writer = await asyncio.open_connection(upstream_host, upstream_port)
    except OSError:
        client_writer.close()
        await client_writer.wait_closed()
        return
    await asyncio.gather(
        pipe(client_reader, upstream_writer),
        pipe(upstream_reader, client_writer),
        return_exceptions=True,
    )


async def main() -> None:
    raw_map = os.environ.get("CYBERBENCH_GATEWAY_MAP")
    if not raw_map:
        raise SystemExit("CYBERBENCH_GATEWAY_MAP is required")
    port_map = json.loads(raw_map)
    servers = []
    for listen_port, upstream in port_map.items():
        host, port = upstream["host"], int(upstream["port"])
        server = await asyncio.start_server(
            lambda reader, writer, host=host, port=port: handle_client(reader, writer, host, port),
            "0.0.0.0",
            int(listen_port),
        )
        servers.append(server)
        print(f"forwarding :{listen_port} -> {host}:{port}", flush=True)
    await asyncio.gather(*(server.serve_forever() for server in servers))


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        sys.exit(0)
