FROM python:3.12-slim
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends tmux asciinema && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY engine.py /app/engine.py
RUN mkdir -p /logs/agent /logs/verifier
CMD ["sleep","infinity"]
