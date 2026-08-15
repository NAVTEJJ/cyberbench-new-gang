#!/bin/sh

# !!! forward all COM1-COM4 to stdio
qemu-system-i386 \
	-no-reboot \
	-nographic \
	-monitor none \
	-hda chall.bin \
	-chardev stdio,id=char0,mux=on \
  	-serial chardev:char0 \
  	-serial chardev:char0 \
  	-serial chardev:char0 \
  	-serial chardev:char0
