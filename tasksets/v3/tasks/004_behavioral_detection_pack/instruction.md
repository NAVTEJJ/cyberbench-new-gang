# Build the Meridian behavioral detection pack

Implement `detect(events)` in `/app/detector.py`.

Your detector must return at most one evidence-bearing alert for each exact
family name:

- device_code_takeover
- ci_secret_exfil
- service_account_lateral

Supporting materials are available under `/app/reference/` and `/app/data/`.

Run the visible evaluator with:

```bash
python3 /app/tools/evaluate_dev.py --app /app
```
