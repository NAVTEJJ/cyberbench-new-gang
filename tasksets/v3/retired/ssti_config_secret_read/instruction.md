# SSTI Secret Read Exploit

The target uses a Jinja-like renderer with object traversal exposed. Craft `/src/payload.txt` that reads `current_app.config["FLAG"]` through globals traversal. The verifier checks exploit semantics, not an exact string.
