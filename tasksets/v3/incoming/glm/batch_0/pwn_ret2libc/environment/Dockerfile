FROM python:3.12

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      ca-certificates \
      curl \
      file \
      git \
      gdb \
      iproute2 \
      iputils-ping \
      jq \
      netcat-openbsd \
      procps \
      tmux \
      unzip \
      vim-tiny \
      wget \
    && rm -rf /var/lib/apt/lists/*

RUN python -m pip install --no-cache-dir \
      "beautifulsoup4>=4.12" \
      "requests>=2.32" \
      "pwntools==4.15.0"

RUN mkdir -p /app /logs/agent /logs/verifier

COPY challenge/ /app/challenge/

WORKDIR /app
CMD ["sleep", "infinity"]
