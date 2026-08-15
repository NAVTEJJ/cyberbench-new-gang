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
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
RUN mkdir -p /app /logs/agent /logs/verifier
COPY assets/web_bad /app/web_bad
COPY assets/web_bad/bad.html /app/bad.html
