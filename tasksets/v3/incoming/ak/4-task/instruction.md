# Rotating-Key IoT Replay and Delegation Gateway

Implement `Gateway` in `/app/engine.py`.

Telemetry uses HMAC-SHA256 over the documented canonical byte encoding. Each device has current and previous key epochs, separate 128-message sliding replay windows per epoch, timestamp bounds, sensor ranges, and a boot counter. Key rotation accepts the previous epoch only during its grace deadline; windows must never bleed across epochs or boots.

Commands require an unexpired delegation chain rooted at the gateway, strict attenuation of capability bits and device scope, canonical signatures at every hop, and a per-device 64-entry command-nonce window. Reject malformed chains, cycles, privilege amplification, confused-deputy device changes, and replay. Every rejection is side-effect free. Successful telemetry and commands update only their corresponding replay state.

Use constant-time MAC comparison. Hidden tests cover out-of-order packets, window shifts of 127/128/129, epoch rollover, boot resets, grace boundaries, delegated capability attenuation, chain reordering, and rejected-request rollback.
