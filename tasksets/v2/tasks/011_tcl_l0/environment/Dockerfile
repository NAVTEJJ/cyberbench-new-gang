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
COPY assets/tcl /app/tcl
COPY assets/tcl/tcl /app/tcl.bin
COPY assets/tcl/libc.so.6 /app/libc.so.6
COPY assets/tcl/tcl.c /app/tcl.c
RUN chmod +x /app/tcl/tcl /app/tcl.bin
