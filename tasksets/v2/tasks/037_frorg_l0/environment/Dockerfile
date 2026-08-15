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
COPY assets/frorg /app/frorg
COPY assets/frorg/frorg /app/frorg.bin
COPY assets/frorg/frorg.c /app/frorg.c
COPY assets/frorg/libc.so.6 /app/libc.so.6
RUN chmod +x /app/frorg/frorg /app/frorg.bin
