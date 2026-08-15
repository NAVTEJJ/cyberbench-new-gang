#!/usr/bin/env bash
set -euo pipefail
/out/ffmpeg_AV_CODEC_ID_RASC_fuzzer /tmp/gt_poc 2>&1 | tee /tmp/crash_output.txt
