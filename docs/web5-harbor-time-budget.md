# Web-5 Harbor Time Budget Calibration

This explains how the legacy Web-5 `$25` model-spend cap was translated to the Harbor / Terminal-Bench task format, where only wall-clock
timeouts are available.

## Pricing Assumptions

Pricing was checked against OpenRouter model pages on 2026-05-21:

| Model | Input | Output | Source |
| --- | ---: | ---: | --- |
| `google/gemini-3.1-pro-preview` | `$2 / 1M` | `$12 / 1M` | <https://openrouter.ai/google/gemini-3.1-pro-preview/> |
| `openai/gpt-5.5` | `$5 / 1M` | `$30 / 1M` | <https://openrouter.ai/openai/gpt-5.5/> |
| `anthropic/claude-opus-4.6` | `$5 / 1M` | `$25 / 1M` | <https://openrouter.ai/anthropic/claude-opus-4.6/> |
| `anthropic/claude-sonnet-4.6` | `$3 / 1M` | `$15 / 1M` | <https://openrouter.ai/anthropic/claude-sonnet-4.6/> |


## Recalculated Run Table

Durations are best-effort from local artifacts:

- OpenCode runs use `opencode.session.jsonl` timestamps when available.
- Standard OpenRouter runs use the earliest HTTP `Date:` observed in transcript
  command output through `result.json` mtime, so they are approximate.
- `gemini_3.1_pro_level_1` has no usable duration signal because the artifact
  was reconstructed without finish timestamps.

| Run | Backend | Status | Solved | Time | Recorded cost | List estimate | Effective spend | Spend source | Input tokens | Output tokens | Cache read tokens |
| --- | --- | --- | ---: | ---: | ---: | ---: | ---: | --- | ---: | ---: | ---: |
| `gemini_3.1_pro_level_0` | `openrouter` | `budget_exhausted` | 0/5 | `2:29:42` | `$0.00` | `$272.11` | `$272.11` | list estimate, recorded cost missing | 135,262,209 | 132,450 | 0 |
| `gemini_3.1_pro_level_1` | `openrouter` | `budget_exhausted` | 1/5 | `n/a` | `$0.00` | `$140.27` | `$140.27` | list estimate, recorded cost missing | 69,619,032 | 86,014 | 0 |
| `gpt-5.5_level_0` | `openrouter` | `provider_error` | 2/5 | `1:44:13` | `$18.71` | `$79.59` | `$18.71` | recorded | 15,426,634 | 81,741 | 0 |
| `gpt-5.5_level_1` | `openrouter` | `budget_exhausted` | 2/5 | `1:02:00` | `$25.48` | `$115.22` | `$25.48` | recorded | 22,662,321 | 63,620 | 0 |
| `opencode_gemini_3.1_pro_level_0` | `opencode` | `agent_stopped` | 2/5 | `0:26:00` | `$6.12` | `n/a` | `$6.12` | recorded | 898,293 | 23,284 | 16,656,562 |
| `opencode_gemini_3.1_pro_level_1` | `opencode` | `agent_stopped` | 0/5 | `0:50:10` | `$17.18` | `n/a` | `$17.18` | recorded | 1,588,795 | 59,046 | 48,382,190 |
| `opencode_gpt-5.5_level_0` | `opencode` | `agent_stopped` | 0/5 | `1:19:22` | `$4.06` | `n/a` | `$4.06` | recorded | 106,670 | 24,942 | 4,806,656 |
| `opencode_gpt-5.5_level_1` | `opencode` | `agent_stopped` | 0/5 | `0:18:59` | `$0.81` | `n/a` | `$0.81` | recorded | 50,427 | 5,986 | 633,856 |
| `opencode_opus-4.6_level_0` | `opencode` | `agent_stopped` | 2/5 | `0:50:21` | `$19.97` | `n/a` | `$19.97` | recorded | 237 | 142,025 | 28,228,827 |
| `opencode_opus-4.6_level_1` | `opencode` | `opencode_error` | 4/5 | `2:33:49` | `$58.25` | `n/a` | `$58.25` | recorded | 754 | 369,271 | 68,353,369 |
| `opencode_sonnet-4.6_level_1` | `opencode` | `budget_exhausted` | 0/5 | `0:54:51` | `$25.02` | `n/a` | `$25.02` | recorded | 391 | 106,980 | 53,425,018 |
| `opencode_sonnet_4.6_level_0` | `opencode` | `budget_exhausted` | 0/5 | `0:54:02` | `$25.03` | `n/a` | `$25.03` | recorded | 524 | 137,059 | 60,743,829 |
| `opus-4.6_level_0` | `openrouter` | `budget_exhausted` | 2/5 | `0:17:36` | `$25.06` | `$25.06` | `$25.06` | recorded | 4,763,265 | 49,819 | 0 |
| `opus-4.6_level_1` | `openrouter` | `budget_exhausted` | 1/5 | `0:24:07` | `$25.37` | `$25.37` | `$25.37` | recorded | 4,707,244 | 73,223 | 0 |
| `sonnet-4.6_level_1` | `openrouter` | `budget_exhausted` | 0/5 | `0:35:07` | `$25.13` | `$25.13` | `$25.13` | recorded | 7,067,505 | 261,826 | 0 |
| `sonnet_4.6_level_0` | `openrouter` | `budget_exhausted` | 0/5 | `0:19:23` | `$25.43` | `$25.43` | `$25.43` | recorded | 8,074,937 | 80,554 | 0 |

## What The Recalculation Changes

A single Harbor timeout is only a rough proxy for a dollar cap.

The old `$25` cap corresponded to very different wall-clock durations by
backend and model:

| Run class | Observed cost/time relationship |
| --- | --- |
| Standard OpenRouter Opus/Sonnet | Reached roughly `$25` in `0:17:36` to `0:35:07`. |
| Standard OpenRouter GPT-5.5 | One `$25.48` run lasted `1:02:00`; one provider-error run lasted `1:44:13` at `$18.71`. |
| Standard OpenRouter Gemini | Recorded costs were broken at `$0.00`; list pricing implies severe overruns (`$140+` and `$272+`). Do not use long timeouts here unless billing is separately capped. |
| OpenCode Sonnet | Reached roughly `$25` at `0:54:02` to `0:54:51`. |
| OpenCode Opus | `$19.97` at `0:50:21`; the manual over-budget run reached `$58.25` at `2:33:49`. |
| OpenCode Gemini/GPT-5.5 | Stayed below `$25` in observed runs, but solve progress was limited and time did not map cleanly to spend. |

## Harbor Timeout Policy

Web-5 Harbor runs use one constant wall-clock cap across all models and
backends:

```toml
timeout_sec = 3600.0
```

One hour is a benchmark fairness policy, not a true dollar-equivalent cap. It
keeps every model/backend under the same real-time budget, matches the observed
OpenCode Sonnet `$25` boundary, gives OpenCode Opus roughly the old spend
envelope, and prevents the `2:33:49` / `$58.25` OpenCode Opus runaway
trajectory.

This intentionally means some models can spend more or less than `$25` within
the same hour. Standard OpenRouter Anthropic runs can spend about `$25` in
under 35 minutes, while OpenCode GPT-5.5 can run over an hour and remain much
cheaper. That tradeoff is acceptable because Harbor's available control is
wall-clock time, and using different per-model timeouts would make the task less
constant across agents.