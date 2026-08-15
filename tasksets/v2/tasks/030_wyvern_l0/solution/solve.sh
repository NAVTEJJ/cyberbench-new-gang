#!/usr/bin/env bash
set -euo pipefail

# Wyvern (network forensics): parse the libpcap capture (stdlib struct, no scapy). Split by
# direction (server port 9009). Reassemble the server->client stream by TCP sequence number (the
# packets are shuffled in the capture), parse the bespoke "WVTP" frames: WELCOME (0x02) gives the
# server nonce, HELLO (0x01, client->server) gives the client nonce -> session key = XOR of the
# two. Each DATA (0x10) payload is reverse( byte ^ key[(seq+j)%4] ^ ((seq*7+j)&0xff) ); invert and
# concatenate in seq order to rebuild the flag. The /health HTTP packet is a decoy.

python3 - <<'PY'
import struct
import urllib.request

BASE = "http://target:8256"
pcap = urllib.request.urlopen(BASE + "/session.pcap", timeout=30).read()

magic = struct.unpack("<I", pcap[:4])[0]
end = "<" if magic == 0xA1B2C3D4 else ">"
off = 24
cli, srv = [], []
while off + 16 <= len(pcap):
    _, _, incl, _ = struct.unpack(end + "IIII", pcap[off:off + 16]); off += 16
    pkt = pcap[off:off + incl]; off += incl
    if len(pkt) < 34 or pkt[12:14] != b"\x08\x00":
        continue
    ip = pkt[14:]; ihl = (ip[0] & 0x0F) * 4
    if ip[9] != 6:                                   # TCP only
        continue
    iptot = struct.unpack("!H", ip[2:4])[0]; ip = ip[:iptot]
    tcp = ip[ihl:]
    sport, dport = struct.unpack("!HH", tcp[:4])
    seq = struct.unpack("!I", tcp[4:8])[0]
    doff = (tcp[12] >> 4) * 4
    payload = tcp[doff:]
    if dport == 9009:
        cli.append((seq, payload))
    elif sport == 9009:
        srv.append((seq, payload))

# client nonce from HELLO
cli_nonce = None
for _, p in sorted(cli):
    if p[:2] == b"WV" and p[2] == 0x01:
        cli_nonce = p[7:7 + struct.unpack(">H", p[5:7])[0]]
        break

# reassemble server stream by TCP seq, then parse frames
stream = b"".join(p for _, p in sorted(srv))
frames, i = [], 0
while i + 7 <= len(stream) and stream[i:i + 2] == b"WV":
    typ = stream[i + 2]; seq = struct.unpack(">H", stream[i + 3:i + 5])[0]
    ln = struct.unpack(">H", stream[i + 5:i + 7])[0]
    frames.append((typ, seq, stream[i + 7:i + 7 + ln])); i += 7 + ln

srv_nonce = next(pl for t, s, pl in frames if t == 0x02)
key = bytes(cli_nonce[k] ^ srv_nonce[k] for k in range(4))

out = bytearray()
for typ, seq, pl in sorted([f for f in frames if f[0] == 0x10], key=lambda f: f[1]):
    t = pl[::-1]
    out += bytes(t[j] ^ key[(seq + j) % 4] ^ ((seq * 7 + j) & 0xFF) for j in range(len(t)))
flag = out.decode()

with open("/app/flags.txt", "w") as f:
    f.write(flag.strip() + "\n")
print("reassembled WVTP by TCP seq, inverted transform, flag:", flag)
PY
