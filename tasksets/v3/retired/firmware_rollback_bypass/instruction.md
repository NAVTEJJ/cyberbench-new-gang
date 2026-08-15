# Firmware Update Verification Bypass

The update verifier compares versions lexicographically and fails open on unknown critical extensions when a legacy compatibility flag is set. Craft `/src/update.json` for version `9.9.9-legacy` that downgrades channel `stable` while being accepted by the flawed verifier.
