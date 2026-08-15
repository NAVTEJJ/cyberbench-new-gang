FROM python:3.12

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      ca-certificates \
      curl \
      file \
      git \
      jq \
      netcat-openbsd \
      procps \
      tshark \
      tcpdump \
      tmux \
      unzip \
      vim-tiny \
      wget \
      binutils \
    && rm -rf /var/lib/apt/lists/*

RUN python -m pip install --no-cache-dir "requests>=2.32"

RUN mkdir -p /app /logs/agent /logs/verifier

COPY challenge/ /app/challenge/

WORKDIR /app
CMD ["sleep", "infinity"]
