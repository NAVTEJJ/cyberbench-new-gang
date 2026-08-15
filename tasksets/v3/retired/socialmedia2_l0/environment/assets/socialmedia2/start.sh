#!/usr/bin/env bash
set -euo pipefail

cd /ctf
python3 /ctf/unhackable2.py &
node /ctf/admin_bot.js
