# Gargantuan

Gargantuan stores several large inputs in one stack buffer.

This task includes the original challenge binary, source, and matching libc for
local analysis:

- `gargantuan`
- `gargantuan.c`
- `libc.so.6`

The program copies each raw read into storage after checking only `strlen()`.
