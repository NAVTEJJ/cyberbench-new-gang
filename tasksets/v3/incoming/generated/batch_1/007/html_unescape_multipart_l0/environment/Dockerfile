FROM python:3.12-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
      ca-certificates \
      curl \
      dnsutils \
      git \
      iputils-ping \
      jq \
      netcat-openbsd \
      nmap \
      tmux \
      wget \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /app /logs/agent /logs/verifier /tests

WORKDIR /app
EXPOSE 5000
CMD ["python3", "/app/app.py"]
