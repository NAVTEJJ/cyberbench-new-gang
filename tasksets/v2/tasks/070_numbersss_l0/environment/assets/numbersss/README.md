# Numbersss

Sometimes computer numbers can be so harddd.

This task includes the original challenge binary, source, and matching libc for
local analysis:

- `numbersss`
- `numbersss.c`
- `libc.so.6`

The service binary prints a libc leak, asks how many bytes to read, and then
reads that many bytes into a small stack buffer.
