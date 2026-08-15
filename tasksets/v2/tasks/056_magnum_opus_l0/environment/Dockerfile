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
      procps \
      asciinema \
      tmux \
      vim-tiny \
      wget \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
RUN mkdir -p /app /logs/agent /logs/verifier
COPY assets/magnum-opus/dist/magnum_opus.py /app/magnum_opus.py
