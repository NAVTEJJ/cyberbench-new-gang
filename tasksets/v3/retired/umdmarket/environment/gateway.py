from __future__ import annotations

import asyncio
import json
import os
import socket
import sys


class UpstreamProtocol(asyncio.DatagramProtocol):
    def __init__(self, gateway: "GatewayProtocol", client_addr) -> None:
        self.gateway = gateway
        self.client_addr = client_addr

    def datagram_received(self, data: bytes, addr) -> None:
        self.gateway.transport.sendto(data, self.client_addr)


class GatewayProtocol(asyncio.DatagramProtocol):
    def __init__(self, upstream_host: str, upstream_port: int) -> None:
        self.upstream_host = upstream_host
        self.upstream_port = upstream_port
        self.transport = None
        self.upstream_addr = None
        self.upstreams = {}
        self.pending = {}

    def connection_made(self, transport) -> None:
        self.transport = transport
        infos = socket.getaddrinfo(
            self.upstream_host,
            self.upstream_port,
            type=socket.SOCK_DGRAM,
        )
        self.upstream_addr = infos[0][4]

    def datagram_received(self, data: bytes, client_addr) -> None:
        if client_addr in self.pending:
            self.pending[client_addr].append(data)
            return
        transport = self.upstreams.get(client_addr)
        if transport is None:
            self.pending[client_addr] = [data]
            asyncio.create_task(self._create_upstream_and_send(data, client_addr))
            return
        transport.sendto(data)

    async def _create_upstream_and_send(self, data: bytes, client_addr) -> None:
        loop = asyncio.get_running_loop()
        transport, _ = await loop.create_datagram_endpoint(
            lambda: UpstreamProtocol(self, client_addr),
            remote_addr=self.upstream_addr,
        )
        self.upstreams[client_addr] = transport
        queued = self.pending.pop(client_addr, [data])
        for packet in queued:
            transport.sendto(packet)


async def main() -> None:
    raw_map = os.environ.get("CYBERBENCH_GATEWAY_MAP")
    if not raw_map:
        raise SystemExit("CYBERBENCH_GATEWAY_MAP is required")
    port_map = json.loads(raw_map)
    loop = asyncio.get_running_loop()
    transports = []
    for listen_port, upstream in port_map.items():
        host, port = upstream["host"], int(upstream["port"])
        transport, _ = await loop.create_datagram_endpoint(
            lambda host=host, port=port: GatewayProtocol(host, port),
            local_addr=("0.0.0.0", int(listen_port)),
        )
        transports.append(transport)
        print(f"forwarding udp :{listen_port} -> {host}:{port}", flush=True)
    try:
        await asyncio.Future()
    finally:
        for transport in transports:
            transport.close()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        sys.exit(0)
