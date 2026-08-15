#!/usr/bin/env python3
"""Summarize Cyber-Bench Harbor jobs/ trials and legacy runs/ artifacts."""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter, defaultdict, deque
from datetime import datetime
from pathlib import Path
from textwrap import shorten


ISSUE_PATTERNS = [
    "timed out",
    "timed_out",
    "command not found",
    "module not found",
    "modulenotfounderror",
    "no such file",
    "permission denied",
    "syntax error",
    "unterminated quoted string",
    "not configured",
    "internal server error",
    "connection refused",
    "could not resolve",
    "temporary failure",
    "unauthenticated",
    "forbidden",
]

ENV_PATTERNS = [
    "module not found",
    "modulenotfounderror",
    "command not found",
    "not configured",
    "no such file",
    "permission denied",
    "could not resolve",
    "temporary failure",
    "unauthenticated",
    "unable to prepare context",
    "docker compose command failed",
    "read-only file system",
]

SHELL_TOOL_NAMES = frozenset(
    {
        "bash",
        "shell",
        "run_terminal_cmd",
        "terminal",
        "execute_command",
        "execute",
    }
)

FLAG_PATH_MARKERS = (
    "/app/flags.txt",
    "/logs/agent/flags.txt",
    "/app/submissions.txt",
)


def load_json(path: Path) -> dict:
    if not path.exists():
        return {}
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def iter_jsonl(path: Path):
    if not path.exists():
        return
    with path.open("r", encoding="utf-8") as handle:
        for line_no, line in enumerate(handle, 1):
            line = line.strip()
            if not line:
                continue
            try:
                yield line_no, json.loads(line)
            except json.JSONDecodeError as exc:
                yield line_no, {"event": "parse_error", "error": str(exc), "raw": line[:500]}


def parse_arguments(raw: str) -> dict:
    try:
        parsed = json.loads(raw or "{}")
        return parsed if isinstance(parsed, dict) else {}
    except json.JSONDecodeError:
        return {"raw": raw}


def one_line(text: str, limit: int) -> str:
    text = re.sub(r"\s+", " ", text or "").strip()
    return shorten(text, width=limit, placeholder="...")


def issue_matches(text: str) -> list[str]:
    lowered = (text or "").lower()
    return [pattern for pattern in ISSUE_PATTERNS if pattern in lowered]


def env_matches(text: str) -> list[str]:
    lowered = (text or "").lower()
    return [pattern for pattern in ENV_PATTERNS if pattern in lowered]


def resolve_target(raw: str) -> Path:
    candidate = Path(raw)
    if candidate.exists():
        return candidate
    for root in ("jobs", "runs"):
        matches = sorted(Path(root).glob(f"**/{raw}"))
        dirs = [path for path in matches if path.is_dir()]
        if len(dirs) == 1:
            return dirs[0]
        if len(dirs) > 1:
            print(f"Multiple matching directories under {root}/:", file=sys.stderr)
            for path in dirs:
                print(f"  {path}", file=sys.stderr)
            sys.exit(2)
    return candidate


def detect_format(path: Path) -> str:
    if not path.is_dir():
        return "unknown"
    result_path = path / "result.json"
    if not result_path.is_file():
        return "unknown"
    result = load_json(result_path)
    child_trials = list_trial_dirs(path)
    if child_trials and not (path / "verifier").is_dir():
        return "harbor_job"
    if (path / "verifier").is_dir() or (path / "agent").is_dir():
        return "harbor_trial"
    if "stats" in result and "n_total_trials" in result:
        return "harbor_job"
    if (path / "transcript.jsonl").is_file() or result.get("bundle_id"):
        return "legacy_run"
    return "unknown"


def list_trial_dirs(job_dir: Path) -> list[Path]:
    trials: list[Path] = []
    for child in sorted(job_dir.iterdir()):
        if not child.is_dir():
            continue
        if child.name in {"agent", "verifier", "artifacts"}:
            continue
        if (child / "result.json").is_file():
            trials.append(child)
    return trials


def step_message_text(message: object) -> str:
    if isinstance(message, str):
        return message
    if isinstance(message, list):
        parts: list[str] = []
        for item in message:
            if isinstance(item, dict):
                if item.get("type") == "text":
                    parts.append(str(item.get("text", "")))
                elif "text" in item:
                    parts.append(str(item["text"]))
            elif isinstance(item, str):
                parts.append(item)
        return "\n".join(part for part in parts if part)
    return str(message or "")


def tool_call_command(arguments: dict) -> str:
    for key in ("command", "cmd", "script"):
        value = arguments.get(key)
        if isinstance(value, str) and value.strip():
            return value
    nested = arguments.get("input")
    if isinstance(nested, dict):
        return tool_call_command(nested)
    return json.dumps(arguments, sort_keys=True) if arguments else ""


def is_flag_write_command(command: str) -> bool:
    lowered = command.lower()
    return any(marker in lowered for marker in FLAG_PATH_MARKERS)


def extract_flag_preview(command: str) -> str:
    match = re.search(r"([A-Za-z0-9_]+\{[^\n\r'\"\\]+?\})", command)
    if match:
        flag = match.group(1)
        return flag[:24] + ("..." if len(flag) > 24 else "")
    return one_line(command, 48)


def elapsed_seconds_from_iso(start: str | None, end: str | None) -> float | None:
    if not start or not end:
        return None
    try:
        start_dt = datetime.fromisoformat(start.replace("Z", "+00:00"))
        end_dt = datetime.fromisoformat(end.replace("Z", "+00:00"))
    except ValueError:
        return None
    return (end_dt - start_dt).total_seconds()


def normalize_harbor_result(trial_result: dict, verifier_details: dict) -> dict:
    config = trial_result.get("config") or {}
    agent_cfg = config.get("agent") or {}
    agent_info = trial_result.get("agent_info") or {}
    agent_result = trial_result.get("agent_result") or {}
    verifier_result = trial_result.get("verifier_result") or {}
    rewards = verifier_result.get("rewards") or {}
    task_path = (trial_result.get("task_id") or {}).get("path") or (config.get("task") or {}).get("path")
    reward = verifier_details.get("reward")
    if reward is None:
        reward = rewards.get("reward")
    solved = verifier_details.get("solved_service_ids") or []
    unsolved = verifier_details.get("unsolved_service_ids") or []
    scored_count = len(solved) + len(unsolved)
    return {
        "format": "harbor",
        "task_path": task_path,
        "trial_name": trial_result.get("trial_name"),
        "agent": agent_info.get("name") or agent_cfg.get("name"),
        "model": agent_cfg.get("model_name") or (agent_info.get("model_info") or {}).get("name"),
        "reward": reward,
        "solved_service_count": len(solved),
        "scored_service_count": scored_count or None,
        "solved_service_ids": solved,
        "unsolved_service_ids": unsolved,
        "submitted_flags": verifier_details.get("submitted_flags") or [],
        "cost_usd": agent_result.get("cost_usd"),
        "prompt_tokens": agent_result.get("n_input_tokens"),
        "completion_tokens": agent_result.get("n_output_tokens"),
        "exception_type": (trial_result.get("exception_info") or {}).get("exception_type"),
        "exception_message": (trial_result.get("exception_info") or {}).get("exception_message"),
        "started_at": trial_result.get("started_at"),
        "finished_at": trial_result.get("finished_at"),
        "elapsed_seconds": elapsed_seconds_from_iso(
            trial_result.get("started_at"),
            trial_result.get("finished_at"),
        ),
    }


def collect_from_trajectory(
    trajectory_path: Path,
    *,
    commands: list[dict],
    flag_writes: list[dict],
    assistant_notes: list[dict],
    issues: list[dict],
    env_issues: list[dict],
    ports: Counter,
    event_counts: Counter,
) -> None:
    if not trajectory_path.is_file():
        return
    try:
        trajectory = json.loads(trajectory_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        issues.append(
            {
                "step": None,
                "line": None,
                "kind": "trajectory_parse_error",
                "detail": str(exc),
            }
        )
        return

    event_counts["harbor.trajectory"] += 1
    for step in trajectory.get("steps") or []:
        if not isinstance(step, dict):
            continue
        step_id = step.get("step_id")
        source = step.get("source")
        message = step_message_text(step.get("message"))
        if source == "agent" and message and message != "(tool use)":
            assistant_notes.append({"step": step_id, "text": message})
            for match in issue_matches(message):
                issues.append(
                    {
                        "step": step_id,
                        "line": None,
                        "kind": match,
                        "detail": one_line(message, 240),
                        "source": "trajectory",
                    }
                )

        tool_calls = step.get("tool_calls") or []
        observation = step.get("observation") or {}
        results_by_id: dict[str, str] = {}
        if isinstance(observation, dict):
            for result in observation.get("results") or []:
                if not isinstance(result, dict):
                    continue
                call_id = str(result.get("source_call_id") or "")
                content = result.get("content")
                if isinstance(content, list):
                    text = step_message_text(content)
                else:
                    text = str(content or "")
                if call_id:
                    results_by_id[call_id] = text

        for tool_call in tool_calls:
            if not isinstance(tool_call, dict):
                continue
            function_name = str(tool_call.get("function_name") or "")
            arguments = tool_call.get("arguments") or {}
            if not isinstance(arguments, dict):
                arguments = {}
            call_id = str(tool_call.get("tool_call_id") or "")
            command = tool_call_command(arguments)
            output = results_by_id.get(call_id, "")
            if function_name not in SHELL_TOOL_NAMES and not command:
                continue

            shell_result = {
                "ok": not issue_matches(output) and "error" not in output.lower()[:200],
                "exit_code": None,
                "stdout": output,
                "stderr": "",
                "timed_out": "timed out" in output.lower(),
            }
            commands.append(
                {
                    "step": step_id,
                    "line": None,
                    "tool": function_name or "shell",
                    "arguments": arguments,
                    "id": call_id,
                    "command": command,
                    "timeout_seconds": None,
                    "result": shell_result,
                    "source": "trajectory",
                }
            )
            for text in (command, output):
                for port in re.findall(r"\b(8[0-9]{3})\b", text):
                    ports[port] += 1
            failed = shell_result.get("timed_out") or not shell_result.get("ok")
            matches = issue_matches(output)
            if failed or matches:
                issue = {
                    "step": step_id,
                    "line": None,
                    "kind": "shell_failure" if failed else ",".join(matches),
                    "detail": one_line(output or command, 320),
                    "command": command,
                    "source": "trajectory",
                }
                issues.append(issue)
                if env_matches(output):
                    env_issues.append(issue)

            if is_flag_write_command(command):
                flag_writes.append(
                    {
                        "step": step_id,
                        "command_preview": one_line(command, 180),
                        "flag_preview": extract_flag_preview(command),
                        "output_preview": one_line(output, 180),
                    }
                )


def collect_from_command_dirs(
    agent_dir: Path,
    *,
    commands: list[dict],
    issues: list[dict],
    env_issues: list[dict],
    ports: Counter,
    event_counts: Counter,
) -> None:
    if not agent_dir.is_dir():
        return
    index = 0
    while True:
        command_dir = agent_dir / f"command-{index}"
        if not command_dir.is_dir():
            break
        command_path = command_dir / "command.txt"
        stdout_path = command_dir / "stdout.txt"
        stderr_path = command_dir / "stderr.txt"
        return_code_path = command_dir / "return-code.txt"
        command = command_path.read_text(encoding="utf-8", errors="replace") if command_path.is_file() else ""
        stdout = stdout_path.read_text(encoding="utf-8", errors="replace") if stdout_path.is_file() else ""
        stderr = stderr_path.read_text(encoding="utf-8", errors="replace") if stderr_path.is_file() else ""
        exit_code: int | None = None
        if return_code_path.is_file():
            try:
                exit_code = int(return_code_path.read_text(encoding="utf-8").strip())
            except ValueError:
                exit_code = None
        result = {
            "ok": exit_code in (None, 0),
            "exit_code": exit_code,
            "stdout": stdout,
            "stderr": stderr,
            "timed_out": False,
        }
        event_counts["harbor.command_dir"] += 1
        commands.append(
            {
                "step": index,
                "line": None,
                "tool": "shell",
                "arguments": {"command": command},
                "id": f"command-{index}",
                "command": command,
                "timeout_seconds": None,
                "result": result,
                "source": "command_dir",
            }
        )
        for text in (command, stdout, stderr):
            for port in re.findall(r"\b(8[0-9]{3})\b", text):
                ports[port] += 1
        text = "\n".join(part for part in (stdout, stderr) if part)
        failed = exit_code not in (None, 0)
        matches = issue_matches(text)
        if failed or matches:
            issue = {
                "step": index,
                "line": None,
                "kind": "shell_failure" if failed else ",".join(matches),
                "detail": one_line(text or command, 320),
                "command": command,
                "source": "command_dir",
            }
            issues.append(issue)
            if env_matches(text):
                env_issues.append(issue)
        index += 1


def collect_harbor_trial(trial_dir: Path) -> dict:
    trial_result = load_json(trial_dir / "result.json")
    verifier_details = load_json(trial_dir / "verifier" / "details.json")
    commands: list[dict] = []
    flag_writes: list[dict] = []
    assistant_notes: list[dict] = []
    issues: list[dict] = []
    env_issues: list[dict] = []
    ports: Counter = Counter()
    event_counts: Counter = Counter()

    exception_info = trial_result.get("exception_info")
    if exception_info:
        message = str(exception_info.get("exception_message") or "")
        exc_type = str(exception_info.get("exception_type") or "trial_exception")
        issues.append(
            {
                "step": None,
                "line": None,
                "kind": exc_type,
                "detail": one_line(message, 400),
                "source": "result.json",
            }
        )
        if env_matches(message):
            env_issues.append(issues[-1])

    agent_dir = trial_dir / "agent"
    trajectory_path = agent_dir / "trajectory.json"
    if trajectory_path.is_file():
        collect_from_trajectory(
            trajectory_path,
            commands=commands,
            flag_writes=flag_writes,
            assistant_notes=assistant_notes,
            issues=issues,
            env_issues=env_issues,
            ports=ports,
            event_counts=event_counts,
        )
    elif not commands:
        collect_from_command_dirs(
            agent_dir,
            commands=commands,
            issues=issues,
            env_issues=env_issues,
            ports=ports,
            event_counts=event_counts,
        )

    exception_path = trial_dir / "exception.txt"
    if exception_path.is_file():
        text = exception_path.read_text(encoding="utf-8", errors="replace")
        for match in issue_matches(text):
            issue = {
                "step": None,
                "line": None,
                "kind": match,
                "detail": one_line(text, 320),
                "source": "exception.txt",
            }
            issues.append(issue)
            if env_matches(text):
                env_issues.append(issue)

    return {
        "format": "harbor_trial",
        "trial_dir": trial_dir,
        "result": normalize_harbor_result(trial_result, verifier_details),
        "raw_trial_result": trial_result,
        "verifier_details": verifier_details,
        "event_counts": event_counts,
        "commands": commands,
        "flag_writes": flag_writes,
        "submit_attempts": [],
        "assistant_notes": assistant_notes,
        "issues": issues,
        "env_issues": env_issues,
        "ports": ports,
        "start": {},
        "finish": {},
        "opencode_session_usage": {},
        "opencode_session_stop_reason": None,
    }


def collect_harbor_job(job_dir: Path) -> dict:
    trials = [collect_harbor_trial(trial_dir) for trial_dir in list_trial_dirs(job_dir)]
    job_result = load_json(job_dir / "result.json")
    return {
        "format": "harbor_job",
        "job_dir": job_dir,
        "job_result": job_result,
        "trials": trials,
    }


def collect(run_dir: Path) -> dict:
    transcript_path = run_dir / "transcript.jsonl"
    opencode_path = run_dir / "opencode.stdout.jsonl"
    opencode_session_path = run_dir / "opencode.session.jsonl"
    pending_calls: dict[int, deque[dict]] = defaultdict(deque)
    commands = []
    submit_attempts = []
    assistant_notes = []
    issues = []
    env_issues = []
    ports = Counter()
    event_counts = Counter()
    start = {}
    finish = {}
    opencode_session_usage = {}
    opencode_session_stop_reason = None

    for line_no, event in iter_jsonl(transcript_path) or []:
        event_type = event.get("event", "unknown")
        event_counts[event_type] += 1
        step = event.get("step")

        if event_type == "start":
            start = event
            continue
        if event_type == "finish":
            finish = event.get("result", {})
            continue
        if event_type == "parse_error":
            issues.append(
                {
                    "step": step,
                    "line": line_no,
                    "kind": "transcript_parse_error",
                    "detail": event.get("error", ""),
                }
            )
            continue

        if event_type == "assistant":
            message = event.get("message") or {}
            content = message.get("content")
            if content:
                assistant_notes.append({"step": step, "text": content})
                for match in issue_matches(content):
                    issues.append(
                        {
                            "step": step,
                            "line": line_no,
                            "kind": match,
                            "detail": one_line(content, 240),
                        }
                    )
            for call in message.get("tool_calls") or []:
                function = call.get("function") or {}
                name = function.get("name", "")
                arguments = parse_arguments(function.get("arguments", ""))
                pending = {
                    "step": step,
                    "line": line_no,
                    "tool": name,
                    "arguments": arguments,
                    "id": call.get("id"),
                }
                pending_calls[step].append(pending)
                if name == "shell":
                    command = arguments.get("command", arguments.get("raw", ""))
                    commands.append(
                        {
                            **pending,
                            "command": command,
                            "timeout_seconds": arguments.get("timeout_seconds"),
                            "result": None,
                        }
                    )
                    for port in re.findall(r"\b(8[0-9]{3})\b", command):
                        ports[port] += 1
                elif name == "submit_flag":
                    flag = str(arguments.get("flag", ""))
                    submit_attempts.append(
                        {
                            **pending,
                            "flag_preview": flag[:16] + ("..." if len(flag) > 16 else ""),
                            "result": None,
                        }
                    )
            continue

        if event_type == "tool_result":
            call = pending_calls[step].popleft() if pending_calls.get(step) else {}
            result = event.get("result") or {}
            tool = call.get("tool", "unknown")

            if tool == "shell":
                for command in commands:
                    if command.get("id") == call.get("id") and command["result"] is None:
                        command["result"] = result
                        break
                text = "\n".join(
                    str(result.get(key, ""))
                    for key in ("stdout", "stderr")
                    if result.get(key)
                )
                for port in re.findall(r"\b(8[0-9]{3})\b", text):
                    ports[port] += 1
                failed = (
                    result.get("ok") is False
                    or result.get("timed_out") is True
                    or result.get("exit_code") not in (None, 0)
                )
                matches = issue_matches(text)
                if failed or matches:
                    if result.get("timed_out") and not text:
                        detail = "command timed out before producing output"
                    else:
                        detail = one_line(text, 320)
                    issue = {
                        "step": step,
                        "line": line_no,
                        "kind": "shell_failure" if failed else ",".join(matches),
                        "detail": detail,
                        "command": call.get("arguments", {}).get("command", ""),
                    }
                    issues.append(issue)
                    if env_matches(text):
                        env_issues.append(issue)
            elif tool == "submit_flag":
                for attempt in submit_attempts:
                    if attempt.get("id") == call.get("id") and attempt["result"] is None:
                        attempt["result"] = result
                        break
                if result.get("correct") is not True:
                    issues.append(
                        {
                            "step": step,
                            "line": line_no,
                            "kind": "incorrect_flag",
                            "detail": f"submit_flag correct={result.get('correct')} solved_count={result.get('solved_count')}",
                        }
                    )
            else:
                text = json.dumps(result, sort_keys=True)
                if issue_matches(text):
                    issues.append(
                        {
                            "step": step,
                            "line": line_no,
                            "kind": "tool_issue",
                            "detail": one_line(text, 240),
                        }
                    )

    if opencode_session_path.is_file():
        opencode = collect_opencode_session(
            opencode_session_path,
            commands,
            submit_attempts,
            assistant_notes,
            issues,
            env_issues,
            ports,
        )
        event_counts.update(opencode["event_counts"])
        opencode_session_usage = opencode.get("usage") or {}
        opencode_session_stop_reason = opencode.get("stop_reason")
    elif opencode_path.is_file():
        opencode = collect_opencode(opencode_path, commands, submit_attempts, assistant_notes, issues, env_issues, ports)
        event_counts.update(opencode["event_counts"])

    return {
        "start": start,
        "finish": finish,
        "result": load_json(run_dir / "result.json"),
        "event_counts": event_counts,
        "commands": commands,
        "submit_attempts": submit_attempts,
        "assistant_notes": assistant_notes,
        "issues": issues,
        "env_issues": env_issues,
        "ports": ports,
        "opencode_session_usage": opencode_session_usage,
        "opencode_session_stop_reason": opencode_session_stop_reason,
    }


def collect_opencode(
    opencode_path: Path,
    commands: list[dict],
    submit_attempts: list[dict],
    assistant_notes: list[dict],
    issues: list[dict],
    env_issues: list[dict],
    ports: Counter,
) -> dict:
    event_counts = Counter()
    step = 0
    current_step_finished = False
    for line_no, event in iter_jsonl(opencode_path) or []:
        event_type = str(event.get("type", "unknown"))
        event_counts[f"opencode.{event_type}"] += 1
        part = event.get("part") or {}
        if not isinstance(part, dict):
            continue
        if event_type == "step_start":
            step += 1
            current_step_finished = False
            continue
        if event_type == "text":
            text = str(part.get("text") or "")
            if text:
                assistant_notes.append({"step": step, "text": text})
                for match in issue_matches(text):
                    issues.append(
                        {
                            "step": step,
                            "line": line_no,
                            "kind": match,
                            "detail": one_line(text, 240),
                            "source": "opencode",
                        }
                    )
            continue
        if event_type == "tool_use":
            _collect_opencode_tool_use(
                part,
                step=step,
                line_no=line_no,
                commands=commands,
                submit_attempts=submit_attempts,
                issues=issues,
                env_issues=env_issues,
                ports=ports,
            )
            continue
        if event_type == "step_finish":
            current_step_finished = True
            reason = part.get("reason")
            if reason not in (None, "stop", "tool-calls"):
                issues.append(
                    {
                        "step": step,
                        "line": line_no,
                        "kind": f"opencode_finish_{reason}",
                        "detail": f"OpenCode step finished with reason={reason}",
                        "source": "opencode",
                    }
                )
            continue
        if event_type == "error" or "error" in part:
            issues.append(
                {
                    "step": step,
                    "line": line_no,
                    "kind": "opencode_error",
                    "detail": one_line(json.dumps(event, sort_keys=True), 320),
                    "source": "opencode",
                }
            )
    if step and not current_step_finished:
        issues.append(
            {
                "step": step,
                "line": None,
                "kind": "opencode_incomplete_step",
                "detail": "OpenCode event stream ended before the final step_finish event",
                "source": "opencode",
            }
        )
    return {"event_counts": event_counts}


def collect_opencode_session(
    opencode_session_path: Path,
    commands: list[dict],
    submit_attempts: list[dict],
    assistant_notes: list[dict],
    issues: list[dict],
    env_issues: list[dict],
    ports: Counter,
) -> dict:
    events = [event for _, event in iter_jsonl(opencode_session_path) or []]
    event_counts = Counter()
    message_roles: dict[str, str] = {}
    usage = _empty_opencode_usage()
    stop_reason = None

    for event in events:
        event_type = str(event.get("type", "unknown"))
        event_counts[f"opencode_session.{event_type}"] += 1
        if event_type != "message":
            continue
        message_id = event.get("id")
        data = event.get("data")
        if isinstance(message_id, str) and isinstance(data, dict) and isinstance(data.get("role"), str):
            message_roles[message_id] = str(data["role"])

    step = 0
    saw_step_start = False
    current_step_finished = False
    for line_no, event in enumerate(events, 1):
        if event.get("type") != "part":
            continue
        data = event.get("data")
        if not isinstance(data, dict):
            continue
        part_type = str(data.get("type", "unknown"))
        event_counts[f"opencode_session.part.{part_type}"] += 1
        message_id = event.get("message_id")
        role = message_roles.get(message_id) if isinstance(message_id, str) else None

        if part_type == "step-start":
            saw_step_start = True
            step += 1
            current_step_finished = False
            continue
        if not saw_step_start and part_type in ("text", "reasoning", "tool") and (step == 0 or current_step_finished):
            step += 1
            current_step_finished = False

        if part_type in ("text", "reasoning") and role in (None, "assistant"):
            text = str(data.get("text") or "")
            if text:
                assistant_notes.append({"step": step, "text": text})
                for match in issue_matches(text):
                    issues.append(
                        {
                            "step": step,
                            "line": line_no,
                            "kind": match,
                            "detail": one_line(text, 240),
                            "source": "opencode-session",
                        }
                    )
            continue
        if part_type == "tool":
            _collect_opencode_tool_use(
                data,
                step=step,
                line_no=line_no,
                commands=commands,
                submit_attempts=submit_attempts,
                issues=issues,
                env_issues=env_issues,
                ports=ports,
            )
            continue
        if part_type == "step-finish":
            if not saw_step_start and step == 0:
                step = 1
            current_step_finished = True
            usage["steps"] += 1
            _add_opencode_usage_values(usage, data)
            reason = data.get("reason")
            if reason:
                stop_reason = str(reason)
            if reason not in (None, "stop", "tool-calls"):
                issues.append(
                    {
                        "step": step,
                        "line": line_no,
                        "kind": f"opencode_finish_{reason}",
                        "detail": f"OpenCode step finished with reason={reason}",
                        "source": "opencode-session",
                    }
                )
    usage["cost_usd"] = round(float(usage["cost_usd"]), 10)
    return {"event_counts": event_counts, "usage": usage, "stop_reason": stop_reason}


def _collect_opencode_tool_use(
    part: dict,
    *,
    step: int,
    line_no: int,
    commands: list[dict],
    submit_attempts: list[dict],
    issues: list[dict],
    env_issues: list[dict],
    ports: Counter,
) -> None:
    state = part.get("state") or {}
    if not isinstance(state, dict):
        state = {}
    tool = str(part.get("tool") or "")
    tool_input = state.get("input") or {}
    if not isinstance(tool_input, dict):
        tool_input = {}
    metadata = state.get("metadata") or {}
    if not isinstance(metadata, dict):
        metadata = {}
    command = str(tool_input.get("command") or "")
    output = str(state.get("output") or metadata.get("output") or "")
    call_id = str(part.get("callID") or part.get("id") or f"opencode-{line_no}")

    if tool == "bash" and _is_submit_flag_command(command):
        attempt = {
            "step": step,
            "line": line_no,
            "tool": "submit_flag",
            "arguments": {"command": command},
            "id": call_id,
            "flag_preview": _extract_flag_preview(command),
            "result": _opencode_submit_result(output),
            "source": "opencode",
        }
        submit_attempts.append(attempt)
        if not attempt["result"].get("correct"):
            issues.append(
                {
                    "step": step,
                    "line": line_no,
                    "kind": "incorrect_flag",
                    "detail": one_line(output or command, 240),
                    "command": command,
                    "source": "opencode",
                }
            )
        return

    if tool == "bash":
        result = _opencode_shell_result(state, metadata, output)
        commands.append(
            {
                "step": step,
                "line": line_no,
                "tool": "shell",
                "arguments": {"command": command},
                "id": call_id,
                "command": command,
                "timeout_seconds": None,
                "result": result,
                "source": "opencode",
            }
        )
        for text in (command, output):
            for port in re.findall(r"\b(8[0-9]{3})\b", text):
                ports[port] += 1
        failed = result.get("ok") is False or result.get("exit_code") not in (None, 0)
        matches = issue_matches(output)
        if failed or matches:
            issue = {
                "step": step,
                "line": line_no,
                "kind": "shell_failure" if failed else ",".join(matches),
                "detail": one_line(output, 320),
                "command": command,
                "source": "opencode",
            }
            issues.append(issue)
            if env_matches(output):
                env_issues.append(issue)


def _empty_opencode_usage() -> dict:
    return {
        "steps": 0,
        "cost_usd": 0.0,
        "tokens": {
            "input": 0,
            "output": 0,
            "reasoning": 0,
            "cache": {"read": 0, "write": 0},
        },
    }


def _add_opencode_usage_values(usage: dict, source: dict) -> None:
    usage["cost_usd"] += float(source.get("cost") or 0.0)
    tokens = source.get("tokens") or {}
    if not isinstance(tokens, dict):
        tokens = {}
    usage["tokens"]["input"] += int(tokens.get("input") or 0)
    usage["tokens"]["output"] += int(tokens.get("output") or 0)
    usage["tokens"]["reasoning"] += int(tokens.get("reasoning") or 0)
    cache = tokens.get("cache") or {}
    if not isinstance(cache, dict):
        cache = {}
    usage["tokens"]["cache"]["read"] += int(cache.get("read") or 0)
    usage["tokens"]["cache"]["write"] += int(cache.get("write") or 0)


def _opencode_shell_result(state: dict, metadata: dict, output: str) -> dict:
    status = state.get("status")
    exit_code = metadata.get("exit")
    try:
        exit_code = int(exit_code) if exit_code is not None else None
    except (TypeError, ValueError):
        exit_code = None
    return {
        "ok": status == "completed" and exit_code in (None, 0),
        "exit_code": exit_code,
        "stdout": output,
        "stderr": "",
        "timed_out": status == "timed_out",
        "elapsed_seconds": _opencode_elapsed_seconds(state),
    }


def _opencode_elapsed_seconds(state: dict) -> float | None:
    time_data = state.get("time") or {}
    if not isinstance(time_data, dict):
        return None
    start = time_data.get("start")
    end = time_data.get("end")
    if isinstance(start, (int, float)) and isinstance(end, (int, float)) and end >= start:
        return (end - start) / 1000
    return None


def _is_submit_flag_command(command: str) -> bool:
    return bool(re.search(r"(^|[\s./])submit_flag(\s|$)", command))


def _extract_flag_preview(command: str) -> str:
    match = re.search(r"(C(?:YBERBENCH|TF)\{[^'\"\s]+)", command)
    if match:
        flag = match.group(1)
        return flag[:16] + ("..." if len(flag) > 16 else "")
    return one_line(command, 32)


def _opencode_submit_result(output: str) -> dict:
    try:
        parsed = json.loads(output)
    except json.JSONDecodeError:
        parsed = {}
    if isinstance(parsed, dict):
        return parsed
    return {}


def print_harbor_trial_summary(trial_dir: Path, data: dict, max_commands: int, snippet_chars: int) -> None:
    result = data["result"]
    print(f"# Cyber-Bench Harbor Trial Summary: `{trial_dir}`")
    print()
    print("## Result")
    if result:
        fields = [
            ("task_path", "task_path"),
            ("trial_name", "trial_name"),
            ("agent", "agent"),
            ("model", "model"),
            ("reward", "reward"),
            ("solved_service_count", "solved_service_count"),
            ("scored_service_count", "scored_service_count"),
            ("cost_usd", "cost_usd"),
            ("prompt_tokens", "prompt_tokens"),
            ("completion_tokens", "completion_tokens"),
            ("elapsed_seconds", "elapsed_seconds"),
            ("exception_type", "exception_type"),
        ]
        for label, field in fields:
            if result.get(field) is not None:
                print(f"- {label}: `{result[field]}`")
        solved = result.get("solved_service_ids") or []
        unsolved = result.get("unsolved_service_ids") or []
        print(f"- solved_service_ids: {', '.join(solved) if solved else 'none'}")
        if unsolved:
            print(f"- unsolved_service_ids: {', '.join(unsolved)}")
        submitted = result.get("submitted_flags") or []
        if submitted:
            print(f"- submitted_flags: {len(submitted)} flag(s) recorded by verifier")
        if result.get("exception_message"):
            print(f"- exception_message: {one_line(str(result['exception_message']), snippet_chars)}")
    else:
        print("- No trial result.json found.")

    _print_command_sections(data, max_commands, snippet_chars)


def print_harbor_job_summary(job_dir: Path, data: dict, max_commands: int, snippet_chars: int) -> None:
    job_result = data.get("job_result") or {}
    print(f"# Cyber-Bench Harbor Job Summary: `{job_dir}`")
    print()
    print("## Job Result")
    if job_result:
        stats = job_result.get("stats") or {}
        print(f"- n_trials: `{stats.get('n_trials')}`")
        print(f"- n_errors: `{stats.get('n_errors')}`")
        evals = stats.get("evals") or {}
        for eval_name, eval_stats in evals.items():
            metrics = eval_stats.get("metrics") or []
            mean_reward = metrics[0].get("mean") if metrics else None
            print(f"- eval `{eval_name}` mean_reward: `{mean_reward}`")
            reward_stats = eval_stats.get("reward_stats") or {}
            for reward_value, trial_names in reward_stats.get("reward", {}).items():
                joined = ", ".join(trial_names)
                print(f"  - reward {reward_value}: {joined}")
    else:
        print("- No job result.json found.")

    print()
    print("## Trials")
    for trial_data in data.get("trials") or []:
        trial_dir = trial_data.get("trial_dir")
        result = trial_data.get("result") or {}
        reward = result.get("reward")
        solved = result.get("solved_service_count")
        scored = result.get("scored_service_count")
        agent = result.get("agent")
        task_path = result.get("task_path")
        exc = result.get("exception_type")
        line = (
            f"- `{trial_dir.name if trial_dir else 'unknown'}`: "
            f"task=`{task_path}` agent=`{agent}` reward=`{reward}` solved=`{solved}/{scored}`"
        )
        if exc:
            line += f" exception=`{exc}`"
        print(line)

    print()
    print("## Trial Details")
    for trial_data in data.get("trials") or []:
        trial_dir = trial_data.get("trial_dir")
        if not trial_dir:
            continue
        print()
        print_harbor_trial_summary(trial_dir, trial_data, max_commands, snippet_chars)


def _print_command_sections(data: dict, max_commands: int, snippet_chars: int) -> None:
    print()
    print("## Transcript Shape")
    counts = ", ".join(f"{key}={value}" for key, value in sorted(data["event_counts"].items()))
    print(f"- events: {counts or 'none'}")
    print(f"- shell commands: {len(data['commands'])}")
    if data.get("format") == "harbor_trial":
        print(f"- flag file writes: {len(data.get('flag_writes') or [])}")
    else:
        print(f"- submit_flag attempts: {len(data['submit_attempts'])}")
    if data["ports"]:
        top_ports = ", ".join(port for port, _ in data["ports"].most_common(16))
        print(f"- ports mentioned: {top_ports}")

    print()
    if data.get("format") == "harbor_trial":
        print("## Flag File Writes")
        flag_writes = data.get("flag_writes") or []
        if not flag_writes:
            print("- none detected in trajectory tool calls")
        for attempt in flag_writes:
            print(
                f"- step {attempt['step']}: `{attempt['flag_preview']}` "
                f"cmd: `{attempt['command_preview']}`"
            )
    else:
        print("## Submit Flag Attempts")
        if not data["submit_attempts"]:
            print("- none")
        for attempt in data["submit_attempts"]:
            res = attempt.get("result") or {}
            print(
                f"- step {attempt['step']}: `{attempt['flag_preview']}` "
                f"correct={res.get('correct')} solved_count={res.get('solved_count')}"
            )

    print()
    print("## Shell Command Timeline")
    if not data["commands"]:
        print("- none")
    for command in data["commands"][:max_commands]:
        result = command.get("result") or {}
        status = "ok"
        if result.get("timed_out"):
            status = "timed_out"
        elif result.get("ok") is False or result.get("exit_code") not in (None, 0):
            status = f"failed exit={result.get('exit_code')}"
        source = command.get("source")
        source_note = f" ({source})" if source else ""
        print(
            f"- step {command['step']}: {status}{source_note}: "
            f"`{one_line(command.get('command', ''), 180)}`"
        )
        stderr = one_line(str(result.get("stderr", "")), snippet_chars)
        stdout = one_line(str(result.get("stdout", "")), snippet_chars)
        if stderr:
            print(f"  stderr: {stderr}")
        if stdout:
            print(f"  stdout: {stdout}")
    if len(data["commands"]) > max_commands:
        print(f"- ... {len(data['commands']) - max_commands} more commands omitted")

    print()
    print("## Issues And Failure Signals")
    if not data["issues"]:
        print("- none detected by script")
    for issue in data["issues"]:
        print(f"- step {issue.get('step')}: {issue.get('kind')}: {issue.get('detail')}")
        if issue.get("command"):
            print(f"  command: `{one_line(issue['command'], 180)}`")

    print()
    print("## Environment Or Harness Signals")
    if not data["env_issues"]:
        print("- none detected by script")
    for issue in data["env_issues"]:
        print(f"- step {issue.get('step')}: {issue.get('kind')}: {issue.get('detail')}")

    print()
    print("## Assistant Self-Summaries")
    if not data["assistant_notes"]:
        print("- none")
    for note in data["assistant_notes"][-8:]:
        print(f"- step {note['step']}: {one_line(note['text'], snippet_chars)}")


def print_summary(run_dir: Path, data: dict, max_commands: int, snippet_chars: int) -> None:
    if data.get("format") == "harbor_job":
        print_harbor_job_summary(run_dir, data, max_commands, snippet_chars)
        return
    if data.get("format") == "harbor_trial":
        print_harbor_trial_summary(run_dir, data, max_commands, snippet_chars)
        return

    result = data["result"] or data["finish"]
    print(f"# Cyber-Bench Legacy Run Summary: `{run_dir}`")
    print()
    print("## Result")
    if result:
        fields = [
            "bundle_id",
            "model",
            "status",
            "solved_service_count",
            "scored_service_count",
            "steps",
            "elapsed_seconds",
            "cost_usd",
            "prompt_tokens",
            "completion_tokens",
        ]
        for field in fields:
            if field in result:
                print(f"- {field}: `{result[field]}`")
        solved = result.get("solved_service_ids") or []
        unsolved = result.get("unsolved_service_ids") or []
        print(f"- solved_service_ids: {', '.join(solved) if solved else 'none'}")
        if unsolved:
            print(f"- unsolved_service_ids: {', '.join(unsolved)}")
        session_usage = data.get("opencode_session_usage") or {}
        result_usage = result.get("opencode_usage") if isinstance(result.get("opencode_usage"), dict) else {}
        if session_usage and (
            not result_usage
            or (
                float(result_usage.get("cost_usd") or 0.0) == 0.0
                and float(session_usage.get("cost_usd") or 0.0) > 0.0
            )
        ):
            tokens = session_usage.get("tokens") or {}
            print(
                "- inferred_opencode_session_usage: "
                f"steps={session_usage.get('steps')} cost_usd={session_usage.get('cost_usd')} "
                f"input={tokens.get('input')} output={tokens.get('output')} reasoning={tokens.get('reasoning')}"
            )
        if data.get("opencode_session_stop_reason"):
            print(f"- inferred_opencode_stop_reason: `{data['opencode_session_stop_reason']}`")
    else:
        print("- No result.json or finish event found.")

    _print_command_sections(data, max_commands, snippet_chars)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "run",
        help="Harbor job/trial path, legacy run path, or unique directory name under jobs/ or runs/",
    )
    parser.add_argument("--max-commands", type=int, default=80)
    parser.add_argument("--snippet-chars", type=int, default=260)
    args = parser.parse_args()

    target = resolve_target(args.run)
    if not target.exists() or not target.is_dir():
        print(f"Directory not found: {target}", file=sys.stderr)
        return 2

    run_format = detect_format(target)
    if run_format == "harbor_job":
        data = collect_harbor_job(target)
    elif run_format == "harbor_trial":
        data = collect_harbor_trial(target)
    elif run_format == "legacy_run":
        data = collect(target)
        data["format"] = "legacy_run"
    else:
        print(
            f"Unrecognized artifact layout under {target}. "
            "Expected a Harbor job/trial or legacy runs/ directory.",
            file=sys.stderr,
        )
        return 2

    print_summary(target, data, args.max_commands, args.snippet_chars)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
