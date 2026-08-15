FROM localhost/cb-python312-local:latest

WORKDIR /app
RUN mkdir -p /app /logs/agent /logs/verifier
RUN apt-get update \
    && apt-get install -y --no-install-recommends asciinema \
    && rm -rf /var/lib/apt/lists/*
