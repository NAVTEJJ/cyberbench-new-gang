FROM python:3.12@sha256:5b4cd1450900015d505c9801bf953922bc4cf607bfb22ee3c347a348ccccf16d

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
      tmux \
      unzip \
      vim-tiny \
      wget \
    && rm -rf /var/lib/apt/lists/*

RUN python -m pip install --no-cache-dir \
      "beautifulsoup4==4.15.0" \
      "requests==2.34.2" \
      "pwntools==4.15.0"

RUN mkdir -p /app /logs/agent /logs/verifier

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      chromium \
      nodejs \
      npm \
    && rm -rf /var/lib/apt/lists/*

RUN PUPPETEER_SKIP_DOWNLOAD=true npm install --prefix /app puppeteer@^23.0.0

WORKDIR /app
CMD ["sleep", "infinity"]
