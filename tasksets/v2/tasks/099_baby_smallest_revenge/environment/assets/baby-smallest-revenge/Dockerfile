FROM ubuntu:25.04

# Update and install packages
RUN apt-get update
RUN apt-get install -y --no-install-recommends \
    qemu-system-x86 \
    python3 \
    socat \
    cpio

# Copy challenge entrypoint
COPY bzImage /opt/
COPY initramfs.cpio /opt/initramfs.cpio
COPY run.sh /opt/
COPY run.py /opt/
COPY hashcash.py /opt/
COPY flag /opt/

RUN chmod +x /opt/run.sh
RUN chmod +x /opt/run.py
RUN chmod +x /opt/hashcash.py

WORKDIR /opt/

RUN mkdir initramfs
RUN cpio -id -D initramfs < initramfs.cpio 2>/dev/null

# Socat listening port
EXPOSE 1337

# Change entrypoint to launch challenge
CMD ["socat", "TCP-LISTEN:1337,reuseaddr,fork", "EXEC:./run.py"]
