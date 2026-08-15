#!/usr/bin/env python3
"""Find empirical budget frontiers and headroom candidates in Harbor jobs."""

from __future__ import annotations

import argparse
import csv
import html
import json
import math
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable


@dataclass(frozen=True)
class Metric:
    key: str
    title: str
    short_title: str
    formatter: Callable[[float | int | None], str]


@dataclass
class Trial:
    path: str
    job: str
    task: str
    task_path: str
    category: str
    agent: str
    model: str
    reward: float | None
    outcome: str
    exception_type: str
    started_at: str | None
    finished_at: str | None
    agent_seconds: float | None
    wall_seconds: float | None
    cost_usd: float | None
    input_tokens: int | None
    output_tokens: int | None
    cache_tokens: int | None
    total_tokens: int | None
    turns: int | None
    multi_service: bool
    eligible: bool
    exclusion_reason: str


def format_duration(value: float | int | None) -> str:
    if value is None:
        return "n/a"
    seconds = int(round(float(value)))
    hours, remainder = divmod(seconds, 3600)
    minutes, seconds = divmod(remainder, 60)
    if hours:
        return f"{hours}h {minutes:02d}m"
    if minutes:
        return f"{minutes}m {seconds:02d}s"
    return f"{seconds}s"


def format_cost(value: float | int | None) -> str:
    if value is None:
        return "n/a"
    return f"${float(value):,.2f}"


def format_count(value: float | int | None) -> str:
    if value is None:
        return "n/a"
    number = float(value)
    if number >= 1_000_000:
        return f"{number / 1_000_000:.2f}M"
    if number >= 1_000:
        return f"{number / 1_000:.1f}k"
    return f"{int(round(number)):,}"


METRICS = (
    Metric("agent_seconds", "Agent execution time", "Time", format_duration),
    Metric("cost_usd", "Recorded model cost", "Cost", format_cost),
    Metric("total_tokens", "Input + output tokens", "Tokens", format_count),
    Metric("turns", "Model turns / episodes", "Turns", format_count),
)

CATEGORY_LABELS = {
    "ctf": "CTF",
    "mem-vul": "Memory vulnerability",
    "unknown": "Unknown",
}


def load_json(path: Path) -> dict[str, Any] | None:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return None
    return value if isinstance(value, dict) else None


def parse_timestamp(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def elapsed_seconds(start: Any, finish: Any) -> float | None:
    start_dt = parse_timestamp(start)
    finish_dt = parse_timestamp(finish)
    if start_dt is None or finish_dt is None:
        return None
    return max(0.0, (finish_dt - start_dt).total_seconds())


def numeric(value: Any) -> float | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)) and math.isfinite(float(value)):
        return float(value)
    return None


def integer(value: Any) -> int | None:
    number = numeric(value)
    return None if number is None else int(number)


def nested(data: dict[str, Any], *keys: str) -> Any:
    current: Any = data
    for key in keys:
        if not isinstance(current, dict):
            return None
        current = current.get(key)
    return current


def task_category(task_name: str, task_path: str) -> str:
    identity = f"{task_name} {task_path}".lower()
    memory_markers = (
        "memory-vuln-bench/",
        "memory_vul_",
        "memory-vul",
        "memvul_",
    )
    if any(marker in identity for marker in memory_markers):
        return "mem-vul"
    if task_name or task_path:
        return "ctf"
    return "unknown"


def reward_from_result(data: dict[str, Any], details: dict[str, Any] | None) -> float | None:
    if details:
        reward = numeric(details.get("reward"))
        if reward is not None:
            return reward
    rewards = nested(data, "verifier_result", "rewards")
    if isinstance(rewards, dict):
        if numeric(rewards.get("reward")) is not None:
            return numeric(rewards["reward"])
        values = [numeric(value) for value in rewards.values()]
        finite_values = [value for value in values if value is not None]
        if finite_values:
            return sum(finite_values) / len(finite_values)
    return None


def trajectory_turns(trial_dir: Path) -> int | None:
    trajectory = load_json(trial_dir / "agent" / "trajectory.json")
    if not trajectory:
        return None
    steps = trajectory.get("steps")
    if isinstance(steps, list):
        count = sum(
            1
            for step in steps
            if isinstance(step, dict) and step.get("source") == "agent"
        )
        return count or None
    legacy = trajectory.get("trajectory")
    if isinstance(legacy, list):
        count = sum(
            1
            for step in legacy
            if isinstance(step, dict)
            and (step.get("source") == "agent" or step.get("role") == "assistant")
        )
        return count or len(legacy) or None
    return None


def is_multi_service(
    data: dict[str, Any], details: dict[str, Any] | None
) -> bool:
    task_path = str(
        nested(data, "task_id", "path")
        or nested(data, "config", "task", "path")
        or ""
    ).lower()
    if "web-5" in task_path or "web_5_l" in task_path:
        return True
    if not details:
        return False
    solved = details.get("solved_service_ids")
    unsolved = details.get("unsolved_service_ids")
    if not isinstance(solved, list) or not isinstance(unsolved, list):
        return False
    return len(solved) + len(unsolved) > 1


def nearest_job_path(trial_dir: Path, jobs_root: Path) -> str:
    for parent in trial_dir.parents:
        if parent == jobs_root.parent:
            break
        candidate = parent / "result.json"
        if not candidate.is_file():
            continue
        data = load_json(candidate)
        if data and "n_total_trials" in data and "task_name" not in data:
            return str(parent.relative_to(jobs_root))
    return str(trial_dir.parent.relative_to(jobs_root))


def classify_trial(
    data: dict[str, Any],
    reward: float | None,
    agent_seconds: float | None,
    agent_result: dict[str, Any] | None,
) -> tuple[str, bool, str]:
    exception_type = str(nested(data, "exception_info", "exception_type") or "")
    finished_at = data.get("finished_at")
    agent_execution = data.get("agent_execution")
    agent_started = isinstance(agent_execution, dict) and agent_execution.get("started_at")

    if not finished_at and not exception_type and reward is None:
        return "active", False, "active"
    if reward is not None and reward > 0:
        outcome = "solved" if reward >= 1.0 else "partial"
    elif exception_type in {"AgentTimeoutError", "CancelledError", "TimeoutError"}:
        outcome = "timeout"
    elif exception_type:
        outcome = "infra_error" if not agent_started or agent_result is None else "agent_error"
    elif reward == 0:
        outcome = "failed"
    else:
        outcome = "unverified"

    agent_name = str(
        nested(data, "agent_info", "name")
        or nested(data, "config", "agent", "name")
        or ""
    ).lower()
    model = str(
        nested(data, "agent_info", "model_info", "name")
        or nested(data, "config", "agent", "model_name")
        or ""
    ).lower()

    if agent_name == "oracle" or model == "oracle":
        return outcome, False, "oracle"
    if reward is None and outcome != "timeout":
        return outcome, False, "unverified"
    if agent_seconds is None:
        return outcome, False, "no_agent_timing"
    if outcome == "infra_error":
        return outcome, False, "infra_error"
    if not model:
        return outcome, False, "no_model"
    return outcome, True, ""


def parse_trial(result_path: Path, jobs_root: Path) -> Trial | None:
    data = load_json(result_path)
    if not data or "task_name" not in data:
        return None

    trial_dir = result_path.parent
    details = load_json(trial_dir / "verifier" / "details.json")
    reward = reward_from_result(data, details)
    agent_result_raw = data.get("agent_result")
    agent_result = agent_result_raw if isinstance(agent_result_raw, dict) else None
    agent_execution = data.get("agent_execution")
    agent_execution = agent_execution if isinstance(agent_execution, dict) else {}
    agent_seconds = elapsed_seconds(
        agent_execution.get("started_at"), agent_execution.get("finished_at")
    )
    wall_seconds = elapsed_seconds(data.get("started_at"), data.get("finished_at"))
    input_tokens = integer((agent_result or {}).get("n_input_tokens"))
    output_tokens = integer((agent_result or {}).get("n_output_tokens"))
    cache_tokens = integer((agent_result or {}).get("n_cache_tokens"))
    total_tokens = None
    if input_tokens is not None or output_tokens is not None:
        total_tokens = (input_tokens or 0) + (output_tokens or 0)
    turns = integer(nested(agent_result or {}, "metadata", "n_episodes"))
    if turns is None:
        turns = trajectory_turns(trial_dir)
    cost_usd = numeric((agent_result or {}).get("cost_usd"))
    outcome, eligible, exclusion_reason = classify_trial(
        data, reward, agent_seconds, agent_result
    )
    multi_service = is_multi_service(data, details)
    if eligible and multi_service:
        eligible = False
        exclusion_reason = "multi_service"
    task_name = str(
        data.get("task_name") or data.get("trial_name") or trial_dir.name
    )
    task_path = str(
        nested(data, "task_id", "path")
        or nested(data, "config", "task", "path")
        or ""
    )

    return Trial(
        path=str(result_path.relative_to(jobs_root)),
        job=nearest_job_path(trial_dir, jobs_root),
        task=task_name,
        task_path=task_path,
        category=task_category(task_name, task_path),
        agent=str(
            nested(data, "agent_info", "name")
            or nested(data, "config", "agent", "name")
            or "unknown"
        ),
        model=str(
            nested(data, "agent_info", "model_info", "name")
            or nested(data, "config", "agent", "model_name")
            or "unknown"
        ),
        reward=reward,
        outcome=outcome,
        exception_type=str(nested(data, "exception_info", "exception_type") or ""),
        started_at=data.get("started_at") if isinstance(data.get("started_at"), str) else None,
        finished_at=data.get("finished_at") if isinstance(data.get("finished_at"), str) else None,
        agent_seconds=agent_seconds,
        wall_seconds=wall_seconds,
        cost_usd=cost_usd,
        input_tokens=input_tokens,
        output_tokens=output_tokens,
        cache_tokens=cache_tokens,
        total_tokens=total_tokens,
        turns=turns,
        multi_service=multi_service,
        eligible=eligible,
        exclusion_reason=exclusion_reason,
    )


def unfinished_job_counts(jobs_root: Path) -> tuple[int, int]:
    jobs = 0
    trials = 0
    for result_path in jobs_root.rglob("result.json"):
        data = load_json(result_path)
        if not data or "n_total_trials" not in data or "task_name" in data:
            continue
        stats = data.get("stats")
        if not isinstance(stats, dict):
            continue
        active = int(stats.get("n_running_trials") or 0) + int(
            stats.get("n_pending_trials") or 0
        )
        if active:
            jobs += 1
            trials += active
    return jobs, trials


def percentile_cap(values: list[float], preservation: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    index = max(0, math.ceil(preservation * len(ordered)) - 1)
    return ordered[index]


def metric_summary(
    trials: Iterable[Trial], metric: Metric, preservation: float
) -> dict[str, Any]:
    observed = [trial for trial in trials if getattr(trial, metric.key) is not None]
    successes = [
        trial
        for trial in observed
        if trial.reward is not None and trial.reward >= 1.0
    ]
    failures = [trial for trial in observed if trial not in successes]
    success_values = [float(getattr(trial, metric.key)) for trial in successes]
    practical = percentile_cap(success_values, preservation)
    hard = max(success_values) if success_values else None
    late_successes = (
        sum(float(getattr(trial, metric.key)) > practical for trial in successes)
        if practical is not None
        else 0
    )
    failures_over = (
        [
            trial
            for trial in failures
            if float(getattr(trial, metric.key)) > practical
        ]
        if practical is not None
        else []
    )
    avoidable = (
        sum(float(getattr(trial, metric.key)) - practical for trial in failures_over)
        if practical is not None
        else None
    )
    total = sum(float(getattr(trial, metric.key)) for trial in observed)
    preserved = (
        (len(successes) - late_successes) / len(successes)
        if successes and practical is not None
        else None
    )
    return {
        "metric": metric.key,
        "observed_trials": len(observed),
        "successes": len(successes),
        "failures": len(failures),
        "practical_cap": practical,
        "hard_ceiling": hard,
        "successes_preserved": preserved,
        "late_successes": late_successes,
        "failures_beyond_cap": len(failures_over),
        "avoidable_overrun": avoidable,
        "avoidable_overrun_share": avoidable / total if avoidable is not None and total else None,
    }


def summaries_for_models(
    trials: list[Trial], preservation: float
) -> list[dict[str, Any]]:
    by_model: dict[str, list[Trial]] = defaultdict(list)
    for trial in trials:
        by_model[trial.model].append(trial)

    output: list[dict[str, Any]] = []
    for model, model_trials in by_model.items():
        successes = sum(trial.reward is not None and trial.reward >= 1.0 for trial in model_trials)
        row: dict[str, Any] = {
            "model": model,
            "trials": len(model_trials),
            "successes": successes,
            "success_rate": successes / len(model_trials) if model_trials else 0,
            "metrics": {},
        }
        for metric in METRICS:
            row["metrics"][metric.key] = metric_summary(
                model_trials, metric, preservation
            )
        output.append(row)
    return sorted(output, key=lambda row: (-row["trials"], row["model"]))


def median(values: list[float]) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    middle = len(ordered) // 2
    if len(ordered) % 2:
        return ordered[middle]
    return (ordered[middle - 1] + ordered[middle]) / 2


def task_headroom_summary(
    trials: list[Trial], minimum_attempts: int
) -> dict[str, Any]:
    by_task: dict[tuple[str, str], list[Trial]] = defaultdict(list)
    for trial in trials:
        identity = trial.task_path or trial.task
        by_task[(identity, trial.task)].append(trial)

    tasks: list[dict[str, Any]] = []
    for (_, task_name), task_trials in by_task.items():
        successes = [
            trial
            for trial in task_trials
            if trial.reward is not None and trial.reward >= 1.0
        ]
        failures = [trial for trial in task_trials if trial not in successes]
        if successes and failures:
            status = "mixed"
        elif successes:
            status = "solved"
        elif len(task_trials) >= minimum_attempts:
            status = "candidate_review"
        else:
            status = "insufficient_data"

        metric_evidence: dict[str, dict[str, float | None]] = {}
        for metric in METRICS:
            failure_values = [
                float(getattr(trial, metric.key))
                for trial in failures
                if getattr(trial, metric.key) is not None
            ]
            metric_evidence[metric.key] = {
                "failure_median": median(failure_values),
                "failure_max": max(failure_values) if failure_values else None,
            }

        tasks.append(
            {
                "task": task_name,
                "task_path": next(
                    (trial.task_path for trial in task_trials if trial.task_path),
                    "",
                ),
                "status": status,
                "attempts": len(task_trials),
                "successes": len(successes),
                "failures": len(failures),
                "success_rate": len(successes) / len(task_trials),
                "models": sorted({trial.model for trial in task_trials}),
                "metrics": metric_evidence,
                "example_result_paths": [
                    trial.path
                    for trial in sorted(
                        failures or task_trials,
                        key=lambda item: -(item.agent_seconds or 0),
                    )[:3]
                ],
            }
        )

    status_order = {
        "candidate_review": 0,
        "mixed": 1,
        "insufficient_data": 2,
        "solved": 3,
    }
    tasks.sort(
        key=lambda row: (
            status_order[row["status"]],
            -row["failures"],
            -row["attempts"],
            row["task"],
        )
    )
    return {
        "minimum_attempts": minimum_attempts,
        "tasks_observed": len(tasks),
        "candidate_count": sum(
            row["status"] == "candidate_review" for row in tasks
        ),
        "mixed_count": sum(row["status"] == "mixed" for row in tasks),
        "tasks": tasks,
    }


def rounded_operational_cap(metric: Metric, value: float | None) -> float | None:
    if value is None:
        return None
    increments = {
        "agent_seconds": 300,
        "cost_usd": 0.5,
        "total_tokens": 100_000,
        "turns": 5,
    }
    increment = increments[metric.key]
    return math.ceil(value / increment) * increment


def operational_policy(
    trials: list[Trial], metrics: dict[str, dict[str, Any]]
) -> dict[str, Any]:
    successes = [
        trial for trial in trials if trial.reward is not None and trial.reward >= 1.0
    ]
    caps = {
        metric.key: rounded_operational_cap(
            metric, metrics[metric.key]["practical_cap"]
        )
        for metric in METRICS
    }
    independent: dict[str, dict[str, Any]] = {}
    for metric in METRICS:
        observed = [
            trial for trial in successes if getattr(trial, metric.key) is not None
        ]
        retained = [
            trial
            for trial in observed
            if float(getattr(trial, metric.key)) <= float(caps[metric.key])
        ]
        independent[metric.key] = {
            "cap": caps[metric.key],
            "observed_successes": len(observed),
            "retained_successes": len(retained),
            "retention": len(retained) / len(observed) if observed else None,
        }

    jointly_observed = [
        trial
        for trial in successes
        if all(getattr(trial, metric.key) is not None for metric in METRICS)
    ]
    jointly_retained = [
        trial
        for trial in jointly_observed
        if all(
            float(getattr(trial, metric.key)) <= float(caps[metric.key])
            for metric in METRICS
        )
    ]
    return {
        "caps": caps,
        "independent": independent,
        "joint_observed_successes": len(jointly_observed),
        "joint_retained_successes": len(jointly_retained),
        "joint_retention": (
            len(jointly_retained) / len(jointly_observed)
            if jointly_observed
            else None
        ),
    }


def population_summary(
    trials: list[Trial], preservation: float, minimum_headroom_attempts: int
) -> dict[str, Any]:
    successes = [
        trial for trial in trials if trial.reward is not None and trial.reward >= 1.0
    ]
    metrics = {
        metric.key: metric_summary(trials, metric, preservation)
        for metric in METRICS
    }
    return {
        "counts": {
            "trials": len(trials),
            "successes": len(successes),
            "failures": len(trials) - len(successes),
        },
        "metrics": metrics,
        "operational_policy": operational_policy(trials, metrics),
        "models": summaries_for_models(trials, preservation),
        "headroom": task_headroom_summary(trials, minimum_headroom_attempts),
    }


def svg_capture_chart(
    trials: list[Trial], metric: Metric, summary: dict[str, Any]
) -> str:
    observed = [trial for trial in trials if getattr(trial, metric.key) is not None]
    successes = [
        trial
        for trial in observed
        if trial.reward is not None and trial.reward >= 1.0
    ]
    if not observed or not successes:
        return '<div class="empty-chart">Not enough successful observations.</div>'

    width, height = 720, 270
    left, right, top, bottom = 58, 20, 18, 48
    chart_width = width - left - right
    chart_height = height - top - bottom
    max_value = max(float(getattr(trial, metric.key)) for trial in observed) or 1.0

    def x(value: float) -> float:
        return left + min(1.0, max(0.0, value / max_value)) * chart_width

    def y(value: float) -> float:
        return top + (1.0 - value) * chart_height

    ordered_successes = sorted(float(getattr(trial, metric.key)) for trial in successes)
    points = [(left, y(0.0))]
    for index, value in enumerate(ordered_successes, start=1):
        points.append((x(value), y(index / len(ordered_successes))))
    points.append((left + chart_width, points[-1][1]))
    point_text = " ".join(f"{px:.1f},{py:.1f}" for px, py in points)

    grid = []
    labels = []
    for fraction in (0.0, 0.25, 0.5, 0.75, 1.0):
        py = y(fraction)
        grid.append(
            f'<line x1="{left}" y1="{py:.1f}" x2="{left + chart_width}" '
            f'y2="{py:.1f}" class="grid-line"/>'
        )
        labels.append(
            f'<text x="{left - 10}" y="{py + 4:.1f}" text-anchor="end" '
            f'class="axis-label">{int(fraction * 100)}%</text>'
        )
    for fraction in (0.0, 0.25, 0.5, 0.75, 1.0):
        value = max_value * fraction
        px = x(value)
        labels.append(
            f'<text x="{px:.1f}" y="{height - 16}" text-anchor="middle" '
            f'class="axis-label">{html.escape(metric.formatter(value))}</text>'
        )

    rugs = []
    for index, trial in enumerate(observed):
        value = float(getattr(trial, metric.key))
        solved = trial.reward is not None and trial.reward >= 1.0
        y1 = top + chart_height - (13 if solved else 5)
        y2 = top + chart_height
        css_class = "rug-success" if solved else "rug-failure"
        offset = (index % 3) * 1.2
        rugs.append(
            f'<line x1="{x(value) + offset:.1f}" y1="{y1:.1f}" '
            f'x2="{x(value) + offset:.1f}" y2="{y2:.1f}" class="{css_class}"/>'
        )

    caps = []
    practical = summary["practical_cap"]
    hard = summary["hard_ceiling"]
    if practical is not None:
        px = x(float(practical))
        caps.append(
            f'<line x1="{px:.1f}" y1="{top}" x2="{px:.1f}" '
            f'y2="{top + chart_height}" class="cap-practical"/>'
        )
    if hard is not None and hard != practical:
        px = x(float(hard))
        caps.append(
            f'<line x1="{px:.1f}" y1="{top}" x2="{px:.1f}" '
            f'y2="{top + chart_height}" class="cap-hard"/>'
        )

    return (
        f'<svg class="capture-chart" viewBox="0 0 {width} {height}" '
        'role="img" aria-label="Cumulative solve capture by resource budget">'
        + "".join(grid)
        + "".join(labels)
        + "".join(rugs)
        + f'<polyline points="{point_text}" class="capture-line"/>'
        + "".join(caps)
        + "</svg>"
    )


def html_escape(value: Any) -> str:
    return html.escape(str(value))


def percentage(value: float | None) -> str:
    return "n/a" if value is None else f"{value * 100:.1f}%"


def render_html(
    summary: dict[str, Any],
    trials: list[Trial],
    output_path: Path,
) -> None:
    eligible = [trial for trial in trials if trial.eligible]
    category_order = ("ctf", "mem-vul")
    snapshot_items = []
    category_sections = []
    model_rows = []
    evidence_rows = []
    headroom_rows = []
    for section_number, category in enumerate(category_order, start=1):
        label = CATEGORY_LABELS[category]
        category_summary = summary["categories"][category]
        category_trials = [
            trial for trial in eligible if trial.category == category
        ]
        metrics = category_summary["metrics"]
        policy = category_summary["operational_policy"]
        counts = category_summary["counts"]
        raw_timeout = metrics["agent_seconds"]["practical_cap"]
        operational_timeout = policy["caps"]["agent_seconds"]
        snapshot_items.append(
            f"""
            <div class="snapshot {html_escape(category)}">
              <span>{html_escape(label)}</span>
              <strong>{html_escape(format_duration(operational_timeout))}</strong>
              <p>raw breakpoint {html_escape(format_duration(raw_timeout))}</p>
            </div>
            """
        )

        policy_items = "".join(
            f"""
            <div class="policy-item">
              <span>{html_escape(metric.short_title)}</span>
              <strong>{html_escape(metric.formatter(policy["caps"][metric.key]))}</strong>
              <small>{percentage(policy["independent"][metric.key]["retention"])} single-cap retention</small>
            </div>
            """
            for metric in METRICS
        )
        metric_cards = []
        for metric in METRICS:
            stats = metrics[metric.key]
            metric_cards.append(
                f"""
                <section class="metric-panel">
                  <div class="metric-head">
                    <div>
                      <p class="eyebrow">{html_escape(metric.title)}</p>
                      <h2>{html_escape(metric.formatter(stats["practical_cap"]))}</h2>
                    </div>
                    <div class="metric-meta">
                      <span><b>{percentage(stats["successes_preserved"])}</b> solves retained</span>
                      <span><b>{stats["failures_beyond_cap"]}</b> failures beyond cap</span>
                    </div>
                  </div>
                  {svg_capture_chart(category_trials, metric, stats)}
                  <div class="legend">
                    <span><i class="line practical"></i>95% cap</span>
                    <span><i class="line hard"></i>latest solve: {html_escape(metric.formatter(stats["hard_ceiling"]))}</span>
                    <span><i class="tick success"></i>solve</span>
                    <span><i class="tick failure"></i>failure</span>
                  </div>
                </section>
                """
            )
        category_sections.append(
            f"""
            <section class="category-section" id="{html_escape(category)}">
              <div class="section-head">
                <div><p class="eyebrow">0{section_number} / {html_escape(label)}</p><h3>{html_escape(label)} budget frontier</h3></div>
                <p>{counts["trials"]} policy trials: {counts["successes"]} verified solves and {counts["failures"]} failures.</p>
              </div>
              <div class="policy-band">{policy_items}</div>
              <p class="policy-note"><strong>Combined {html_escape(label)} policy:</strong> all four rounded caps retain {policy["joint_retained_successes"]} of {policy["joint_observed_successes"]} fully observed solves ({percentage(policy["joint_retention"])}).</p>
              <div class="metrics">{"".join(metric_cards)}</div>
            </section>
            """
        )

        category_candidates = [
            row
            for row in category_summary["headroom"]["tasks"]
            if row["status"] == "candidate_review"
        ]
        if not category_candidates:
            headroom_rows.append(
                "<tr>"
                f"<td><strong>{html_escape(label)}</strong></td>"
                '<td colspan="7"><span class="muted">No repeated zero-solve candidates.</span></td>'
                "</tr>"
            )
        for row in category_candidates[:20]:
            metric_evidence = row["metrics"]
            task_detail = row["task_path"] or "task path unavailable"
            headroom_rows.append(
                "<tr>"
                f"<td><strong>{html_escape(label)}</strong></td>"
                f"<td><strong>{html_escape(row['task'])}</strong><small>{html_escape(task_detail)}</small></td>"
                f"<td>{row['attempts']}</td>"
                f"<td>{html_escape(', '.join(row['models']))}</td>"
                f"<td>{html_escape(format_duration(metric_evidence['agent_seconds']['failure_max']))}</td>"
                f"<td>{html_escape(format_cost(metric_evidence['cost_usd']['failure_max']))}</td>"
                f"<td>{html_escape(format_count(metric_evidence['total_tokens']['failure_max']))}</td>"
                f"<td>{html_escape(format_count(metric_evidence['turns']['failure_max']))}</td>"
                "</tr>"
            )

        for row in category_summary["models"]:
            cells = []
            for metric in METRICS:
                stats = row["metrics"][metric.key]
                cells.append(
                    f"<td>{html_escape(metric.formatter(stats['practical_cap']))}"
                    f"<small>{html_escape(metric.formatter(stats['hard_ceiling']))} ceiling</small></td>"
                )
            model_rows.append(
                "<tr>"
                f"<td><strong>{html_escape(label)}</strong></td>"
                f"<td>{html_escape(row['model'])}</td>"
                f"<td>{row['trials']}</td>"
                f"<td>{row['successes']} <small>{percentage(row['success_rate'])}</small></td>"
                + "".join(cells)
                + "</tr>"
            )

        category_failures = sorted(
            [
                trial
                for trial in category_trials
                if trial.reward is None or trial.reward < 1.0
            ],
            key=lambda trial: -(trial.agent_seconds or 0),
        )[:6]
        category_successes = sorted(
            [
                trial
                for trial in category_trials
                if trial.reward is not None and trial.reward >= 1.0
            ],
            key=lambda trial: -(trial.agent_seconds or 0),
        )[:5]
        evidence_rows.append(
            f'<tr class="group-row"><td colspan="8">{html_escape(label)}</td></tr>'
        )
        for trial in sorted(
            category_failures + category_successes,
            key=lambda item: -(item.agent_seconds or 0),
        ):
            evidence_rows.append(
                "<tr>"
                f"<td><span class=\"status {html_escape(trial.outcome)}\">{html_escape(trial.outcome)}</span></td>"
                f"<td><strong>{html_escape(label)}</strong></td>"
                f"<td><strong>{html_escape(trial.task)}</strong><small>{html_escape(trial.job)}</small></td>"
                f"<td>{html_escape(trial.model)}</td>"
                f"<td>{html_escape(format_duration(trial.agent_seconds))}</td>"
                f"<td>{html_escape(format_cost(trial.cost_usd))}</td>"
                f"<td>{html_escape(format_count(trial.total_tokens))}</td>"
                f"<td>{html_escape(format_count(trial.turns))}</td>"
                "</tr>"
            )

    exclusion_rows = "".join(
        f"<tr><td>{html_escape(reason)}</td><td>{count}</td></tr>"
        for reason, count in summary["exclusions"].items()
    )

    generated = html_escape(summary["generated_at"])
    css = """
    :root {
      --paper: #f2f0e9;
      --ink: #161815;
      --muted: #656861;
      --rule: #bbbdb4;
      --cyan: #087f8c;
      --green: #2d7d46;
      --red: #c7432f;
      --amber: #c58a10;
      --panel: #fbfaf6;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      color: var(--ink);
      background: var(--paper);
      font-family: "IBM Plex Sans", "Helvetica Neue", sans-serif;
      letter-spacing: 0;
    }
    body::before {
      content: "";
      position: fixed;
      inset: 0;
      pointer-events: none;
      opacity: .18;
      background-image: linear-gradient(rgba(0,0,0,.035) 1px, transparent 1px);
      background-size: 100% 4px;
    }
    main { width: min(1480px, 94vw); margin: 0 auto; padding: 44px 0 72px; }
    header {
      border-top: 7px solid var(--ink);
      border-bottom: 1px solid var(--ink);
      padding: 24px 0 30px;
      display: grid;
      grid-template-columns: minmax(0, 1.35fr) minmax(360px, .65fr);
      gap: 36px;
      align-items: end;
    }
    h1, h2, h3, p { margin: 0; }
    h1 {
      max-width: 900px;
      font-family: "IBM Plex Mono", "Courier New", monospace;
      font-size: clamp(36px, 5.8vw, 86px);
      line-height: .96;
      font-weight: 700;
    }
    h2 { font: 700 38px/1 "IBM Plex Mono", monospace; }
    h3 { font: 700 20px/1.2 "IBM Plex Mono", monospace; }
    .kicker, .eyebrow {
      color: var(--cyan);
      font: 700 12px/1.2 "IBM Plex Mono", monospace;
      text-transform: uppercase;
      letter-spacing: 0;
    }
    .lede { max-width: 640px; color: var(--muted); font-size: 17px; line-height: 1.55; }
    .snapshot-stack { display: grid; grid-template-columns: repeat(2, 1fr); gap: 18px; }
    .snapshot { border-left: 4px solid var(--amber); padding-left: 16px; }
    .snapshot.mem-vul { border-left-color: var(--cyan); }
    .snapshot strong { display: block; font: 700 24px/1.2 "IBM Plex Mono", monospace; }
    .snapshot span { color: var(--muted); font-size: 11px; text-transform: uppercase; }
    .snapshot p { color: var(--muted); font-size: 12px; }
    .summary-strip {
      display: grid;
      grid-template-columns: repeat(5, 1fr);
      border-bottom: 1px solid var(--ink);
    }
    .summary-stat { padding: 20px 18px; border-right: 1px solid var(--rule); }
    .summary-stat:first-child { padding-left: 0; }
    .summary-stat:last-child { border-right: 0; }
    .summary-stat strong { display: block; font: 700 26px/1.1 "IBM Plex Mono", monospace; }
    .summary-stat span { color: var(--muted); font-size: 12px; text-transform: uppercase; }
    .policy-band {
      display: grid;
      grid-template-columns: repeat(4, 1fr);
      margin-top: 28px;
      border-top: 1px solid var(--ink);
      border-bottom: 1px solid var(--ink);
      background: var(--panel);
    }
    .policy-item { padding: 18px; border-right: 1px solid var(--rule); }
    .policy-item:last-child { border-right: 0; }
    .policy-item span, .policy-item small { display: block; color: var(--muted); font-size: 11px; text-transform: uppercase; }
    .policy-item strong { display: block; margin: 5px 0; font: 700 28px/1 "IBM Plex Mono", monospace; }
    .policy-note { padding: 14px 18px; border-bottom: 1px solid var(--ink); color: var(--muted); font-size: 13px; line-height: 1.5; }
    .policy-note strong { color: var(--ink); }
    .category-section { padding-top: 8px; }
    .section-head {
      display: flex;
      justify-content: space-between;
      align-items: end;
      gap: 24px;
      margin: 42px 0 18px;
    }
    .section-head p { max-width: 700px; color: var(--muted); line-height: 1.5; }
    .metrics { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); border-top: 1px solid var(--ink); border-left: 1px solid var(--ink); }
    .metric-panel { min-width: 0; padding: 22px; background: var(--panel); border-right: 1px solid var(--ink); border-bottom: 1px solid var(--ink); }
    .metric-head { display: flex; justify-content: space-between; gap: 20px; align-items: end; }
    .metric-meta { display: grid; gap: 4px; text-align: right; color: var(--muted); font-size: 12px; }
    .metric-meta b { color: var(--ink); }
    .capture-chart { width: 100%; height: auto; margin-top: 16px; overflow: visible; }
    .grid-line { stroke: #d5d6d0; stroke-width: 1; }
    .axis-label { fill: var(--muted); font: 10px "IBM Plex Mono", monospace; }
    .capture-line { fill: none; stroke: var(--cyan); stroke-width: 3; }
    .rug-success { stroke: var(--green); stroke-width: 2; opacity: .72; }
    .rug-failure { stroke: var(--red); stroke-width: 1.5; opacity: .45; }
    .cap-practical { stroke: var(--amber); stroke-width: 2; stroke-dasharray: 6 4; }
    .cap-hard { stroke: var(--green); stroke-width: 2; stroke-dasharray: 2 4; }
    .legend { display: flex; flex-wrap: wrap; gap: 14px; color: var(--muted); font-size: 11px; }
    .legend span { display: inline-flex; align-items: center; gap: 6px; }
    .line { display: inline-block; width: 18px; border-top: 2px dashed; }
    .line.practical { border-color: var(--amber); }
    .line.hard { border-color: var(--green); }
    .tick { display: inline-block; height: 10px; border-left: 2px solid; }
    .tick.success { border-color: var(--green); }
    .tick.failure { border-color: var(--red); }
    .empty-chart { min-height: 220px; display: grid; place-items: center; color: var(--muted); }
    .table-wrap { overflow-x: auto; border-top: 1px solid var(--ink); }
    table { width: 100%; border-collapse: collapse; background: rgba(251,250,246,.72); }
    th, td { padding: 13px 12px; border-bottom: 1px solid var(--rule); text-align: left; vertical-align: top; font-size: 13px; }
    th { color: var(--muted); font: 700 11px/1.2 "IBM Plex Mono", monospace; text-transform: uppercase; background: var(--paper); }
    td small { display: block; margin-top: 4px; color: var(--muted); }
    .group-row td { background: var(--ink); color: var(--paper); font: 700 11px/1 "IBM Plex Mono", monospace; text-transform: uppercase; }
    .status { display: inline-block; padding: 3px 6px; border: 1px solid currentColor; font: 700 10px/1 "IBM Plex Mono", monospace; text-transform: uppercase; }
    .status.solved { color: var(--green); }
    .status.timeout, .status.failed, .status.agent_error { color: var(--red); }
    .status.partial { color: var(--amber); }
    .muted { color: var(--muted); }
    .method {
      display: grid;
      grid-template-columns: 1.3fr .7fr;
      gap: 36px;
      padding: 28px 0;
      border-top: 1px solid var(--ink);
      border-bottom: 1px solid var(--ink);
    }
    .method p { color: var(--muted); line-height: 1.6; }
    .method strong { color: var(--ink); }
    .callout { border-left: 5px solid var(--cyan); padding-left: 18px; }
    footer { margin-top: 24px; display: flex; justify-content: space-between; color: var(--muted); font-size: 11px; font-family: "IBM Plex Mono", monospace; }
    @media (max-width: 900px) {
      header, .method { grid-template-columns: 1fr; }
      .metrics { grid-template-columns: 1fr; }
      .summary-strip { grid-template-columns: repeat(2, 1fr); }
      .policy-band { grid-template-columns: repeat(2, 1fr); }
      .summary-stat { border-bottom: 1px solid var(--rule); }
      .summary-stat:first-child { padding-left: 18px; }
    }
    @media (max-width: 560px) {
      main { width: 92vw; padding-top: 22px; }
      h1 { font-size: 38px; }
      .summary-strip { grid-template-columns: 1fr; }
      .policy-band { grid-template-columns: 1fr; }
      .snapshot-stack { grid-template-columns: 1fr; }
      .summary-stat { border-right: 0; }
      .metric-head { align-items: start; flex-direction: column; }
      .metric-meta { text-align: left; }
      .section-head { align-items: start; flex-direction: column; }
    }
    """

    document = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Cyber-Bench Budget Frontier</title>
  <style>{css}</style>
</head>
<body>
<main>
  <header>
    <div>
      <p class="kicker">Cyber-Bench / empirical cutoff analysis</p>
      <h1>Budget frontier</h1>
    </div>
    <div class="snapshot-stack">{"".join(snapshot_items)}</div>
  </header>

  <section class="summary-strip">
    <div class="summary-stat"><strong>{summary["artifact_counts"]["trial_results"]}</strong><span>trial results scanned</span></div>
    <div class="summary-stat"><strong>{summary["categories"]["ctf"]["counts"]["trials"]} / {summary["categories"]["ctf"]["counts"]["successes"]}</strong><span>CTF trials / solves</span></div>
    <div class="summary-stat"><strong>{summary["categories"]["mem-vul"]["counts"]["trials"]} / {summary["categories"]["mem-vul"]["counts"]["successes"]}</strong><span>mem-vul trials / solves</span></div>
    <div class="summary-stat"><strong>{summary["artifact_counts"]["eligible_failures"]}</strong><span>model failures</span></div>
    <div class="summary-stat"><strong>{summary["artifact_counts"]["reported_unfinished_trials"]}</strong><span>unfinished slots in metadata</span></div>
  </section>

  {"".join(category_sections)}

  <div class="section-head" id="headroom">
    <div><p class="eyebrow">03 / Headroom review</p><h3>Repeated zero-solve tasks</h3></div>
    <p>These tasks have at least {summary["minimum_headroom_attempts"]} eligible attempts and no verified solve. They are candidates, not confirmed headroom, until trajectories and verifier evidence rule out harness or environment failures.</p>
  </div>
  <div class="table-wrap">
    <table>
      <thead><tr><th>Category</th><th>Task / path</th><th>Attempts</th><th>Models</th><th>Max time</th><th>Max cost</th><th>Max tokens</th><th>Max turns</th></tr></thead>
      <tbody>{"".join(headroom_rows)}</tbody>
    </table>
  </div>

  <div class="section-head" id="models">
    <div><p class="eyebrow">04 / Model sensitivity</p><h3>Category and model both move the frontier</h3></div>
    <p>Models come from each trial's Harbor metadata; category comes from the recorded task identity and path.</p>
  </div>
  <div class="table-wrap">
    <table>
      <thead><tr><th>Category</th><th>Model</th><th>Trials</th><th>Solves</th><th>Time</th><th>Cost</th><th>Tokens</th><th>Turns</th></tr></thead>
      <tbody>{"".join(model_rows)}</tbody>
    </table>
  </div>

  <div class="section-head" id="evidence">
    <div><p class="eyebrow">05 / Boundary evidence</p><h3>Longest solves and failures by category</h3></div>
    <p>Each category contributes its own longest failures and successful boundary cases.</p>
  </div>
  <div class="table-wrap">
    <table>
      <thead><tr><th>Outcome</th><th>Category</th><th>Task / job</th><th>Model</th><th>Time</th><th>Cost</th><th>Tokens</th><th>Turns</th></tr></thead>
      <tbody>{"".join(evidence_rows)}</tbody>
    </table>
  </div>

  <div class="section-head" id="method">
    <div><p class="eyebrow">06 / Method</p><h3>What is allowed to set each X</h3></div>
  </div>
  <section class="method">
    <p class="callout"><strong>Primary populations:</strong> CTF and memory-vulnerability trials are analyzed independently. Both require completed, model-driven Harbor trials with binary verifier rewards and measured agent execution. Reward 1 is a solve; reward 0, timeout, or post-execution agent error is a failure. Repeated failures nominate tasks for headroom review but do not prove a capability gap.</p>
    <div>
      <p><strong>Category rule:</strong> memory-vulnerability namespaces and paths map to mem-vul; all other named benchmark tasks map to CTF. Oracle runs, multi-service fractional trials, active or unverified trials, pre-agent failures, and infrastructure errors are excluded from both.</p>
      <div class="table-wrap"><table><tbody>{exclusion_rows}</tbody></table></div>
    </div>
  </section>

  <footer><span>Generated {generated}</span><span>Source: jobs/**/result.json + verifier/details.json</span></footer>
</main>
</body>
</html>
"""
    output_path.write_text(document, encoding="utf-8")


def write_csv(path: Path, trials: list[Trial]) -> None:
    fields = list(asdict(trials[0]).keys()) if trials else list(Trial.__annotations__)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for trial in trials:
            writer.writerow(asdict(trial))


def write_headroom_csv(path: Path, summary: dict[str, Any]) -> None:
    fields = [
        "category",
        "task",
        "task_path",
        "status",
        "attempts",
        "successes",
        "failures",
        "success_rate",
        "models",
        "failure_median_seconds",
        "failure_max_seconds",
        "failure_median_cost_usd",
        "failure_max_cost_usd",
        "failure_median_tokens",
        "failure_max_tokens",
        "failure_median_turns",
        "failure_max_turns",
        "example_result_paths",
    ]
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for category in ("ctf", "mem-vul", "unknown"):
            for task in summary["categories"][category]["headroom"]["tasks"]:
                metrics = task["metrics"]
                writer.writerow(
                    {
                        "category": category,
                        "task": task["task"],
                        "task_path": task["task_path"],
                        "status": task["status"],
                        "attempts": task["attempts"],
                        "successes": task["successes"],
                        "failures": task["failures"],
                        "success_rate": task["success_rate"],
                        "models": ";".join(task["models"]),
                        "failure_median_seconds": metrics["agent_seconds"][
                            "failure_median"
                        ],
                        "failure_max_seconds": metrics["agent_seconds"][
                            "failure_max"
                        ],
                        "failure_median_cost_usd": metrics["cost_usd"][
                            "failure_median"
                        ],
                        "failure_max_cost_usd": metrics["cost_usd"][
                            "failure_max"
                        ],
                        "failure_median_tokens": metrics["total_tokens"][
                            "failure_median"
                        ],
                        "failure_max_tokens": metrics["total_tokens"][
                            "failure_max"
                        ],
                        "failure_median_turns": metrics["turns"][
                            "failure_median"
                        ],
                        "failure_max_turns": metrics["turns"]["failure_max"],
                        "example_result_paths": ";".join(
                            task["example_result_paths"]
                        ),
                    }
                )


def write_markdown(path: Path, summary: dict[str, Any]) -> None:
    artifact_counts = summary["artifact_counts"]
    category_sections = []
    for category in ("ctf", "mem-vul"):
        label = CATEGORY_LABELS[category]
        category_summary = summary["categories"][category]
        counts = category_summary["counts"]
        metrics = category_summary["metrics"]
        policy = category_summary["operational_policy"]
        policy_rows = []
        frontier_rows = []
        headroom_rows = []
        for metric in METRICS:
            policy_stats = policy["independent"][metric.key]
            metric_stats = metrics[metric.key]
            policy_rows.append(
                "| "
                + " | ".join(
                    [
                        metric.short_title,
                        metric.formatter(policy_stats["cap"]),
                        percentage(policy_stats["retention"]),
                    ]
                )
                + " |"
            )
            frontier_rows.append(
                "| "
                + " | ".join(
                    [
                        metric.short_title,
                        metric.formatter(metric_stats["practical_cap"]),
                        metric.formatter(metric_stats["hard_ceiling"]),
                        percentage(metric_stats["successes_preserved"]),
                        str(metric_stats["failures_beyond_cap"]),
                        metric.formatter(metric_stats["avoidable_overrun"]),
                    ]
                )
                + " |"
            )
        for row in category_summary["headroom"]["tasks"]:
            if row["status"] != "candidate_review":
                continue
            evidence = row["metrics"]
            headroom_rows.append(
                "| "
                + " | ".join(
                    [
                        row["task"].replace("|", "\\|"),
                        str(row["attempts"]),
                        ", ".join(row["models"]).replace("|", "\\|"),
                        format_duration(
                            evidence["agent_seconds"]["failure_max"]
                        ),
                        format_cost(evidence["cost_usd"]["failure_max"]),
                        format_count(evidence["total_tokens"]["failure_max"]),
                        format_count(evidence["turns"]["failure_max"]),
                    ]
                )
                + " |"
            )
        if not headroom_rows:
            headroom_rows.append(
                "| _No repeated zero-solve candidates_ | 0 | n/a | n/a | n/a | n/a | n/a |"
            )
        category_sections.append(
            f"""## {label}

Population: {counts["trials"]} policy trials, {counts["successes"]} verified
solves, and {counts["failures"]} failures.

| Budget | Operational cap | Historical solves retained |
| --- | ---: | ---: |
{chr(10).join(policy_rows)}

Recommended task timeout: **{format_duration(policy["caps"]["agent_seconds"])}**.
Raw empirical breakpoint:
**{format_duration(metrics["agent_seconds"]["practical_cap"])}**.

Enforcing all four rounded caps together retains
**{policy["joint_retained_successes"]}/{policy["joint_observed_successes"]}**
fully observed solves ({percentage(policy["joint_retention"])}).

| Budget | 95%-preserving cap | Latest observed solve | Solves retained | Failures beyond cap | Failure-only overrun |
| --- | ---: | ---: | ---: | ---: | ---: |
{chr(10).join(frontier_rows)}

### Headroom review queue

The following tasks have at least
{category_summary["headroom"]["minimum_attempts"]} eligible attempts and no
verified solve. They are provisional candidates; inspect trajectories,
verifier evidence, and task feasibility before treating them as genuine
headroom.

| Task | Attempts | Models | Max failure time | Max failure cost | Max failure tokens | Max failure turns |
| --- | ---: | --- | ---: | ---: | ---: | ---: |
{chr(10).join(headroom_rows)}
"""
        )
    text = f"""# Cyber-Bench Budget Frontier

Generated from the full `jobs/` artifact snapshot at
`{summary["generated_at"]}`.

{chr(10).join(category_sections)}

## Coverage

- Trial results scanned: {artifact_counts["trial_results"]}
- Binary model trials used for policy: {artifact_counts["eligible_trials"]}
- Verified solves: {artifact_counts["eligible_successes"]}
- Model failures: {artifact_counts["eligible_failures"]}
- Unknown-category policy trials: {artifact_counts["unknown_category_trials"]}
- Unfinished trial slots reported in job metadata: {artifact_counts["reported_unfinished_trials"]}

## Method

CTF and memory-vulnerability tasks are analyzed as separate populations.
Memory-vulnerability namespaces and paths map to `mem-vul`; all other named
benchmark tasks map to `ctf`. Both populations require completed, model-driven
Harbor trials with binary verifier rewards and measured agent execution.

The empirical cap is the smallest observed successful resource value that
retains at least 95% of successful trials. The hard ceiling is the maximum
successful value. These are empirical policy thresholds, not causal estimates:
task mix and model mix can move them as new runs arrive.

The headroom queue is intentionally conservative. Repeated zero-reward model
attempts nominate a task for review, but do not establish human solvability or
rule out environment, harness, or verifier defects.

Oracle runs, multi-service fractional Web-5 trials, active or unverified
trials, pre-agent failures, and infrastructure errors are excluded.
Unfinished counts come from Harbor job metadata and can include abandoned jobs;
they are not used in the cutoff analysis.
"""
    path.write_text(text, encoding="utf-8")


def build_summary(
    jobs_root: Path,
    trials: list[Trial],
    preservation: float,
    minimum_headroom_attempts: int,
) -> dict[str, Any]:
    eligible = [trial for trial in trials if trial.eligible]
    successes = [
        trial for trial in eligible if trial.reward is not None and trial.reward >= 1.0
    ]
    unfinished_jobs, unfinished_trials = unfinished_job_counts(jobs_root)
    exclusions = Counter(
        trial.exclusion_reason for trial in trials if not trial.eligible
    )
    aggregate = population_summary(
        eligible, preservation, minimum_headroom_attempts
    )
    categories = {
        category: population_summary(
            [trial for trial in eligible if trial.category == category],
            preservation,
            minimum_headroom_attempts,
        )
        for category in CATEGORY_LABELS
    }
    return {
        "schema_version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "jobs_root": str(jobs_root),
        "preservation_target": preservation,
        "minimum_headroom_attempts": minimum_headroom_attempts,
        "artifact_counts": {
            "trial_results": len(trials),
            "eligible_trials": len(eligible),
            "eligible_successes": len(successes),
            "eligible_failures": len(eligible) - len(successes),
            "unknown_category_trials": categories["unknown"]["counts"]["trials"],
            "reported_unfinished_jobs": unfinished_jobs,
            "reported_unfinished_trials": unfinished_trials,
        },
        "exclusions": dict(sorted(exclusions.items())),
        "metrics": aggregate["metrics"],
        "operational_policy": aggregate["operational_policy"],
        "models": aggregate["models"],
        "categories": categories,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "jobs",
        nargs="?",
        type=Path,
        default=Path("jobs"),
        help="Harbor jobs directory (default: ./jobs).",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="Output directory (default: <jobs>/.budget-analysis).",
    )
    parser.add_argument(
        "--preserve",
        type=float,
        default=0.95,
        help="Fraction of observed successful trials the practical cap must retain.",
    )
    parser.add_argument(
        "--minimum-headroom-attempts",
        type=int,
        default=2,
        help="Eligible zero-solve attempts required for the review queue.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    jobs_root = args.jobs.resolve()
    output_dir = (
        args.output.resolve()
        if args.output
        else jobs_root / ".budget-analysis"
    )
    if not jobs_root.is_dir():
        raise SystemExit(f"jobs directory not found: {jobs_root}")
    if not 0 < args.preserve <= 1:
        raise SystemExit("--preserve must be in (0, 1]")
    if args.minimum_headroom_attempts < 1:
        raise SystemExit("--minimum-headroom-attempts must be at least 1")

    trials = [
        trial
        for result_path in jobs_root.rglob("result.json")
        if (trial := parse_trial(result_path, jobs_root)) is not None
    ]
    trials.sort(key=lambda trial: (trial.job, trial.task, trial.path))
    summary = build_summary(
        jobs_root,
        trials,
        args.preserve,
        args.minimum_headroom_attempts,
    )

    output_dir.mkdir(parents=True, exist_ok=True)
    write_csv(output_dir / "trials.csv", trials)
    write_headroom_csv(output_dir / "headroom_tasks.csv", summary)
    (output_dir / "summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    write_markdown(output_dir / "summary.md", summary)
    render_html(summary, trials, output_dir / "index.html")

    print(f"Scanned {len(trials)} trial results; {len([t for t in trials if t.eligible])} eligible.")
    for category in ("ctf", "mem-vul"):
        category_summary = summary["categories"][category]
        time_summary = category_summary["metrics"]["agent_seconds"]
        policy_timeout = category_summary["operational_policy"]["caps"][
            "agent_seconds"
        ]
        print(
            f"{CATEGORY_LABELS[category]} timeout: "
            f"{format_duration(policy_timeout)} "
            f"(empirical {format_duration(time_summary['practical_cap'])}; "
            f"hard ceiling {format_duration(time_summary['hard_ceiling'])})."
        )
        print(
            f"{CATEGORY_LABELS[category]} headroom review queue: "
            f"{category_summary['headroom']['candidate_count']} tasks."
        )
    print(f"Report: {output_dir / 'index.html'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
