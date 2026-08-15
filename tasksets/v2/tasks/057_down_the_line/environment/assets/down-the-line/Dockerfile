FROM ubuntu:25.04

# Update and install packages
RUN apt-get update
RUN apt-get install -y --no-install-recommends \
    qemu-system-i386 \
    socat

COPY run.sh /opt/
COPY chall.bin /opt/

RUN chmod +x /opt/run.sh

WORKDIR /opt/

EXPOSE 1337

CMD ["socat", "TCP-LISTEN:1337,reuseaddr", "EXEC:./run.sh"]
