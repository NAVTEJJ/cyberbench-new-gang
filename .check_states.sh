#!/bin/bash
cd /mnt/c/Users/NAVTEJ/Downloads/Cyber-Bench-main
export PATH="$HOME/.local/bin:$PATH"

echo "=== Other session (001/ctr_relay) state ==="
python3 -c "
import json
with open('tasksets/v3/incoming/generated/batch_1/001/.task-factory-runtime/workflow/state.json') as f:
    s = json.load(f)
print('phase:', s.get('phase'))
oj = s.get('jobs',{}).get('oracle',[])
print('oracle jobs:', len(oj))
for t in oj[-2:]:
    print('  trial:', t.get('trial'), 'solved:', t.get('solved'), 'exception:', bool(t.get('exception_info')))
cj = s.get('jobs',{}).get('calibration',[])
print('calibration jobs:', len(cj))
for t in cj[-2:]:
    print('  trial:', t.get('trial'), 'solved:', t.get('solved'), 'exception:', bool(t.get('exception_info')))
"

echo ""
echo "=== My session (002) state ==="
python3 -c "
import json
with open('tasksets/v3/incoming/generated/batch_1/002/.task-factory-runtime/workflow/state.json') as f:
    s = json.load(f)
print('phase:', s.get('phase'))
print('iteration:', s.get('iteration'))
oj = s.get('jobs',{}).get('oracle',[])
print('oracle jobs:', len(oj))
for t in oj[-3:]:
    print('  trial:', t.get('trial'), 'solved:', t.get('solved'), 'exception_type:', (t.get('exception_info') or {}).get('exception_type','none'))
"
