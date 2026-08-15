#!/bin/sh
cd /home/ctf
exec ./ld-linux-x86-64.so.2 --library-path . ./vuln
