#!/bin/bash
set -e
mkdir -p /src
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
cp "$DIR/solution.py" /src/solution.py
