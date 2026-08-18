FROM python:3.12
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl wget nmap netcat-openbsd dnsutils jq git tmux file xxd openssl socat \
    && rm -rf /var/lib/apt/lists/*
RUN mkdir -p /app /logs/agent /logs/verifier /tests
WORKDIR /app
CMD ["sleep", "infinity"]
