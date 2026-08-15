FROM python:3.12

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      ca-certificates \
      curl \
      file \
      git \
      jq \
      procps \
      asciinema \
      tmux \
      vim-tiny \
      wget \
      binutils \
      gdb \
      gcc \
      strace \
      netcat-openbsd \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
RUN mkdir -p /app /logs/agent /logs/verifier
COPY assets/gargantuan /app/gargantuan
COPY assets/gargantuan/gargantuan /app/gargantuan.bin
COPY assets/gargantuan/gargantuan.c /app/gargantuan.c
COPY assets/gargantuan/libc.so.6 /app/libc.so.6
RUN chmod +x /app/gargantuan/gargantuan /app/gargantuan.bin
