# Cyber-Bench Agent Notes

## Project Context

Cyber-Bench is a benchmark for testing whether LLM agents can solve
cybersecurity challenges in controlled environments.

Current direction:

- Create and calibrate new challenges in Harbor task format.
- A good task is valid headroom: human-solvable from the provided interface and
  artifacts, but hard enough to expose capability gaps in frontier models.
- Prefer public CTF inspiration and real vulnerability classes, but do not reuse exact tasks.
- Runnable benchmark packages are separated by release under
  `tasksets/<version>/tasks/`.
- Active generated or experimental tasks may live under `tasksets/<version>/incoming`
  or focused staging folders such as `tasksets/v3-codex/incoming` until reviewed.
- Use `tasksets/v1/tasks/` for the established Web-5 and memory-vul set and
  `tasksets/v2/tasks/` for the imported V2 set.
  Do not rename, normalize, add, delete, or edit anything there during
  unrelated work without explicit approval.
- Models are called through OpenRouter using the repo `.env`; do not require
  separate provider keys.
- Cheap models are used for initial calibration. Do not run costlier models
  unless explicitly requested.

## Harbor Task Format

New tasks should follow the local Harbor layout already used in staged tasksets:

- `task.toml`: task metadata, agent/verifier/build timeouts, tags, and resource
  settings.
- `instruction.md`: concise attacker-facing task description.
- `environment/docker-compose.yaml`: `main` attacker service plus challenge
  services on an internal Docker network.
- `environment/Dockerfile` and `environment/assets/...`: self-contained service
  source and runtime assets.
- `solution/solve.sh`: oracle-grade reference solve that writes the recovered
  flag to `/app/flags.txt`. Should be the actual steps required to solve the tasks not just an echo of the required flag.
- `tests/test.sh` and `tests/grade_flags.py`: verifier entrypoint and flag
  grading.

Behavioral contracts:

- Web/crypto/rev/network/forensics agents write recovered flags to
  `/app/flags.txt`.
- Memory-vul agents write crash output to `/tmp/crash_output.txt`.
- Challenges must be self-contained. Do not require public internet access from
  the attacker container.
- Keep common recon tools available in the attacker image: `curl`, `wget`,
  `nmap`, `netcat`, `dnsutils`, `jq`, and `git`.
- Verifier results, especially `verifier/details.json`, are authoritative for
  solved status. Agent logs and flag writes are evidence, not grading.

## Headroom Standard

Classify task quality by whether the failure reflects a real capability gap.

A valid headroom task:

- Is realistically solvable by a skilled human using only task instructions,
  service behavior, files, source artifacts intentionally exposed by the task,
  and normal local tooling.
- Has a discoverable exploit path. Required headers, topics, opcodes, hook
  names, protocols, credentials, checksum formats, and canonical strings must be
  inferable from public behavior, supplied artifacts, or meaningful errors.
- Does not depend on exact-string guessing, hidden magic constants, or private
  implementation semantics that cannot be recovered uniquely.
- Avoids recipe-level disclosure. Give clues and inspectable surfaces, not a
  step-by-step exploit contract.
- Fails gracefully under common malformed inputs. Bad requests should return
  useful errors instead of permanently poisoning or crashing the service.
- Does not turn missing optional Python packages or niche tools into the main
  obstacle. Agents should have reasonable fallbacks with stdlib and shell tools.
- Has an oracle solution that is deterministic and representative of the intended path.

Invalid headroom examples:

- A service accepts only one undocumented canonical topic or header value and
  all wrong values return the same generic response.
- A firmware or VM task hides an opcode table with no interpreter, metadata, or
  input/output pairs.
- A task says "nonce reuse" but lets the agent directly sign the privileged
  message.
- A supply-chain task requires an undisclosed hook name and gives no metadata or
  error path revealing valid hook values.


## Local Workflow

- Before running Python commands, activate the local virtual environment:

```bash
source .venv/bin/activate
```

- Do not print `.env` contents or API keys.
- Use `--model` for model selection.
- Prefer validation, tests, builds, and oracle checks before paid model runs.
- Choose the taskset path explicitly for every Harbor run.
- `google-web-10` uses local source-built `cyberbench/google-web-10:*` images
  because the upstream Google Artifact Registry images are permission-gated.
  Keep upstream image references as provenance metadata, not the default runtime
  path.
- Docker-backed CTF assets and run outputs are intentionally ignored:
  `resources/`, `runs/`, and `memories/`.
