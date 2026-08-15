#!/usr/bin/env python3
import base64
import gzip
import re
import subprocess
import sys


def main() -> int:
    out = subprocess.run(
        [
            "tshark", "-r", "/app/challenge/capture.pcap",
            "-Y", "dns.flags.response == 0",
            "-T", "fields", "-e", "dns.qry.name",
        ],
        capture_output=True,
        text=True,
        timeout=20,
    )
    print(out.stdout, flush=True)
    sys.stderr.write(out.stderr)
    subdomains = ["exfil.evil", "c2.exfil.evil", "data.exfil.evil", "relay.exfil.evil"]
    chunks_by_sd = {sd: [] for sd in subdomains}
    for line in out.stdout.splitlines():
        qname = line.strip().rstrip(".")
        for sd in subdomains:
            if qname.endswith("." + sd):
                chunks_by_sd[sd].append(qname.split(".")[0])
                break
    combined = ""
    for sd in subdomains:
        combined += "".join(chunks_by_sd[sd])
    if not combined:
        print("no exfil chunks found", file=sys.stderr)
        return 1
    pad = (8 - len(combined) % 8) % 8
    try:
        xored = base64.b32decode(combined + "=" * pad)
    except Exception as e:
        print(f"base32 decode failed: {e}", file=sys.stderr)
        return 1
    decompressed = gzip.decompress(bytes(b ^ 0x5A for b in xored))
    flag = decompressed.decode("latin1", "replace")
    print(flag, flush=True)
    m = re.search(r"[A-Za-z0-9_]+\{[^}]+\}", flag)
    if not m:
        return 1
    print(m.group(0), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
