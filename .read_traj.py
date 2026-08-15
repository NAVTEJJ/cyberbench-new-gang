import json
import pathlib

traj_path = pathlib.Path("/mnt/c/Users/NAVTEJ/Downloads/Cyber-Bench-main/tasksets/v3/incoming/generated/batch_1/004/.task-factory-runtime/jobs/unicode_escape_binstack_l0_target_r3_20260810_040030_422257/unicode_escape_binstack_l0__VnXj57H/agent/trajectory.json")
data = json.loads(traj_path.read_text())

if isinstance(data, list):
    print(f"Entries: {len(data)}")
    # Show last few entries
    for entry in data[-5:]:
        if isinstance(entry, dict):
            role = entry.get("role", entry.get("type", "?"))
            content = str(entry.get("content", entry.get("text", entry.get("message", ""))))
            print(f"\n--- {role} ---")
            print(content[:500])
elif isinstance(data, dict):
    print(f"Keys: {list(data.keys())}")
    for k, v in data.items():
        if isinstance(v, list):
            print(f"\n{k}: {len(v)} items")
            for item in v[-3:]:
                if isinstance(item, dict):
                    print(f"  {json.dumps(item)[:300]}")
        elif isinstance(v, str):
            print(f"\n{k}: {v[:300]}")
        else:
            print(f"\n{k}: {v}")
