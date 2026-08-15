#!/usr/bin/env bash
set -euo pipefail
python3 -c "
import base64
data = 'PD94bWwgZW5jb2Rpbmc9Im5vIjxJU08tMDI0MTgtRU50DlJVPjxJQU46X1NVPhk8QU5ZU35+fn4gPEUgeG1sbnM9Ii8vLy8vLy8vL35+fn5+fn5+fn5+fn5+fn5+fn5+fn5+fn5+fn5+fn5+fn5+fn5+ODg4ODg4ODg4ODg4ODg4ODg4Nzk5OTk5OTk5OS8vLyYjeDg4ODg4ODg4ODg4ODg4ODg4ODg4ODg4ODg4ODg4ODg4ODg4ODg4ODg4ODg4ODg4ODg4ODg4ODg4ODg4ONLHx8fHfn5+fn5+fn5+fn5+fn5+fn5+fn5+fn5+fn5+fn5+fn5+fn5+fn5+fn5+fn5+fn5+fg=='
with open('/tmp/gt_poc', 'wb') as f:
    f.write(base64.b64decode(data))
"
rm -f /tmp/crash_output.txt
for attempt in 1 2 3; do
    /out/libxml2_xml_read_memory_fuzzer /tmp/gt_poc > /tmp/crash_output.txt 2>&1 || true
    cat /tmp/crash_output.txt
    if grep -q "MemorySanitizer: use-of-uninitialized-value" /tmp/crash_output.txt; then
        exit 0
    fi
    if [ "$attempt" != "3" ]; then
        sleep 1
    fi
done

exit 1
