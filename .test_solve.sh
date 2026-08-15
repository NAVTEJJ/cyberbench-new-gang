#!/bin/bash
cd /mnt/c/Users/NAVTEJ/Downloads/Cyber-Bench-main
export PATH="$HOME/.local/bin:$PATH"

TASK_DIR="/mnt/c/Users/NAVTEJ/Downloads/Cyber-Bench-main/tasksets/v3/incoming/generated/batch_1/002/memvul_dblfree_snapshot"
IMG_NAME="memvul_dblfree_test2"

echo "=== Building hardened image ==="
docker build -t "$IMG_NAME" "$TASK_DIR/environment/" 2>&1 | tail -5

echo ""
echo "=== Testing solve.sh (double-free path) ==="
docker run --rm \
  -v "$TASK_DIR/solution/solve.sh:/solve.sh:ro" \
  -v "$TASK_DIR/tests/grade.py:/tests/grade.py:ro" \
  -v "$TASK_DIR/tests/test.sh:/tests/test.sh:ro" \
  "$IMG_NAME" \
  bash -c '
    bash /solve.sh 2>&1 | head -20
    echo ""
    echo "--- crash_output exists? ---"
    ls -la /tmp/crash_output.txt 2>&1
    echo ""
    echo "--- Running verifier ---"
    mkdir -p /logs/verifier
    bash /tests/test.sh 2>&1
    echo ""
    cat /logs/verifier/reward.txt
  ' 2>&1

echo ""
echo "=== Testing decoy path (REINDEX = UAF, not double-free) ==="
docker run --rm "$IMG_NAME" bash -c '
  cat > /tmp/decoy.txt << "EOF"
PUT key1 value1
BEGIN
DEL key1
ROLLBACK
REINDEX
EOF
  /out/kvstore_cmd /tmp/decoy.txt 2>&1 | head -20
' 2>&1
