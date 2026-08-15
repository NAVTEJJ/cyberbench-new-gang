FROM python:3.12

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      ca-certificates \
      curl \
      dnsutils \
      file \
      git \
      iproute2 \
      iputils-ping \
      jq \
      netcat-openbsd \
      nmap \
      poppler-utils \
      procps \
      asciinema \
      tmux \
      unzip \
      vim-tiny \
      wget \
    && rm -rf /var/lib/apt/lists/*

RUN python -m pip install --no-cache-dir \
      "beautifulsoup4>=4.12" \
      "requests>=2.32"

WORKDIR /app
RUN mkdir -p /app /logs/agent /logs/verifier
