#!/bin/sh

musl-gcc -static -Os -s -D FLAG='"dice{mildly_toxic_python_bytecoding}"' printflag.c -o printflag
musl-gcc -static -Os -s -D FLAG='"flag{FAKE_FLAG}"' printflag.c -o printflag-example
