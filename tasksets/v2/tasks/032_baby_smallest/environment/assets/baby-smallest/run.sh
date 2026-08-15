#!/bin/sh

qemu-system-x86_64 \
	-kernel ./bzImage \
	-cpu qemu64,+smap,+smep,+fsgsbase \
	-smp 1 \
	-m 256M \
	-initrd ./initramfs.cpio \
	-append "console=ttyS0 quiet loglevel=3 oops=panic panic_on_warn=1 panic=-1 pti=on page_alloc.shuffle=1" \
	-no-reboot \
	-nographic \
	-monitor /dev/null \
	-drive format=raw,file="$1",if=virtio
