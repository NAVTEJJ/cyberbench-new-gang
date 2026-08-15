#!/bin/bash
export PATH="$HOME/.local/bin:$PATH"
HARBOR=/home/navtej/.local/lib/python3.12/site-packages/harbor

echo "=== oracle agent source ==="
find "$HARBOR" -path "*/oracle*" -o -path "*Oracle*" 2>/dev/null | head -20
echo "=== oracle agent class ==="
grep -rl "class.*Oracle\|oracle.*agent\|OracleAgent" "$HARBOR" --include="*.py" 2>/dev/null | head -10
echo "=== solve.sh handling ==="
grep -rn "solve\.sh\|solution/" "$HARBOR" --include="*.py" 2>/dev/null | head -20
echo "=== single_step agent ==="
cat "$HARBOR/trial/single_step.py" 2>/dev/null | head -80
echo "=== oracle agent file ==="
find "$HARBOR" -name "oracle*.py" 2>/dev/null | head -5
cat "$HARBOR/agents/oracle.py" 2>/dev/null || cat "$HARBOR/agent/oracle.py" 2>/dev/null || echo "oracle.py not found at expected paths"
