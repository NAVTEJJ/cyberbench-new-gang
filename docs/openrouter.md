# OpenRouter Configuration

Cyber-Bench uses OpenRouter as the only model backend for v1. Put the API key in
`.env`:

```env
OPENROUTER_API_KEY=...
```

Choose the model with `--model`, or set a default OpenRouter model id for your
Harbor runs:

```env
CYBERBENCH_MODEL=anthropic/claude-sonnet-4.5
```

If `--model` and `CYBERBENCH_MODEL` are both unset, Harbor will use its normal
agent/model configuration. Passing `--model` on the command line always wins
over the env variable.

Example:

```bash
set -a
source .env
set +a

harbor run \
  --path tasksets/v1/tasks/web_5_l4 \
  --agent terminus-2 \
  --model openrouter/openai/gpt-5.5
```
