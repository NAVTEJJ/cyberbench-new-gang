FROM ubuntu:20.04
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends socat \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /home/ctf
COPY vuln libc.so.6 ld-linux-x86-64.so.2 run.sh /home/ctf/
COPY flag /flag
RUN chmod +x vuln ld-linux-x86-64.so.2 run.sh
EXPOSE 5000
CMD ["socat", "TCP-LISTEN:5000,fork,reuseaddr", "EXEC:./run.sh"]
