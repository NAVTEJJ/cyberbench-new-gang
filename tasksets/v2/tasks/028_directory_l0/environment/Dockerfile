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
COPY assets/directory /app/directory
COPY assets/directory/directory /app/directory.bin
COPY assets/directory/directory.c /app/directory.c
RUN chmod +x /app/directory/directory /app/directory.bin
