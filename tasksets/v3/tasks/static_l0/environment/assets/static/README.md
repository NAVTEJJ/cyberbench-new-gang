# Static

The target is a statically linked non-PIE binary with a stack overflow.

This task includes the original challenge binary and source for local analysis:

- `static`
- `static.c`

The binary reads far more data than the stack buffer can hold.
