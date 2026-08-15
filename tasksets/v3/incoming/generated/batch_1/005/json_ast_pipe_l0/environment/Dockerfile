FROM python:3.12-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
      ca-certificates \
      curl \
      dnsutils \
      file \
      git \
      jq \
      netcat-openbsd \
      nmap \
      procps \
      tmux \
      unzip \
      vim-tiny \
      wget \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir \
      --trusted-host pypi.org \
      --trusted-host files.pythonhosted.org \
      "requests>=2.32"

RUN mkdir -p /app /logs/agent /logs/verifier /tests

WORKDIR /app
CMD ["sleep", "infinity"]
