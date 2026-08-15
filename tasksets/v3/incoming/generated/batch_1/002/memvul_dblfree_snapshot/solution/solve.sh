#!/usr/bin/env bash
set -eu
cat > /tmp/input.txt << 'CMDS'
PUT secret s3cr3t_v4lu3_h3r3
BEGIN
DEL secret
ROLLBACK
DEL secret
CMDS
/out/kvstore_cmd /tmp/input.txt 2>&1 | tee /tmp/crash_output.txt
