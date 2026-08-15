#!/bin/bash
cd /mnt/c/Users/NAVTEJ/Downloads/Cyber-Bench-main
export PATH="$HOME/.local/bin:$PATH"
harbor --version 2>&1
echo "---"
docker info 2>&1 | head -5
echo "---"
docker ps 2>&1 | head -3
