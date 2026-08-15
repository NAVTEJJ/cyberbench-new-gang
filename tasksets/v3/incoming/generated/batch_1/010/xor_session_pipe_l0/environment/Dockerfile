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
      --trusted-host pypi.python.org \
      "flask>=3.0" \
      "requests>=2.32" \
      "cryptography>=42.0" \
      "pycryptodome" \
      "PyJWT>=2.8"

COPY app.py /app/app.py

RUN mkdir -p /app /logs/agent /logs/verifier /tests

WORKDIR /app
EXPOSE 5000
CMD ["sleep", "infinity"]