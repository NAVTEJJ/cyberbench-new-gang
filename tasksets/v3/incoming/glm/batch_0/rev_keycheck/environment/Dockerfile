FROM python:3.12

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      ca-certificates \
      curl \
      file \
      gcc \
      git \
      gdb \
      jq \
      netcat-openbsd \
      procps \
      tmux \
      unzip \
      vim-tiny \
      wget \
      binutils \
    && rm -rf /var/lib/apt/lists/*

RUN python -m pip install --no-cache-dir \
      "pwntools==4.15.0" \
      "requests>=2.32"

RUN mkdir -p /app /logs/agent /logs/verifier

COPY challenge/ /app/challenge/

RUN gcc -O2 -s -o /app/challenge/keycheck /app/challenge/keycheck.c && \
    rm /app/challenge/keycheck.c && \
    chmod +x /app/challenge/keycheck

WORKDIR /app
CMD ["sleep", "infinity"]
