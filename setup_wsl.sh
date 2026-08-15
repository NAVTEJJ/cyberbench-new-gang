#!/bin/bash
set -e
cd ~
echo "=== installing pip to user site (--break-system-packages) ==="
python3 get-pip.py --user --break-system-packages 2>&1 | tail -8
echo "=== pip check ==="
python3 -m pip --version 2>&1
echo "=== installing harbor + requests to user site ==="
python3 -m pip install --user --break-system-packages harbor requests 2>&1 | tail -8
echo "=== versions ==="
python3 -m pip --version
python3 -c "import harbor; print('harbor module:', harbor.__file__)" 2>&1
python3 -c "import requests; print('requests:', requests.__version__)" 2>&1
echo "=== harbor CLI ==="
python3 -m harbor --help 2>&1 | head -3 || echo "no module-as-cli"
which harbor 2>&1 || ls ~/.local/bin/harbor 2>&1 || echo "no harbor bin"
export PATH="$HOME/.local/bin:$PATH"
which harbor 2>&1 && harbor --version 2>&1 || echo "harbor bin not found"
