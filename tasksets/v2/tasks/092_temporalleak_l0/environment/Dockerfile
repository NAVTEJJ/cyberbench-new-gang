FROM python:3.12@sha256:5b4cd1450900015d505c9801bf953922bc4cf607bfb22ee3c347a348ccccf16d

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      ca-certificates \
      curl \
      dnsutils \
      git \
      iproute2 \
      iputils-ping \
      jq \
      netcat-openbsd \
      nmap \
      procps \
      tmux \
      wget \
    && rm -rf /var/lib/apt/lists/*

RUN python -m pip install --no-cache-dir "requests==2.34.2"

WORKDIR /app
RUN mkdir -p /app /logs/agent /logs/verifier
CMD ["sleep", "infinity"]
