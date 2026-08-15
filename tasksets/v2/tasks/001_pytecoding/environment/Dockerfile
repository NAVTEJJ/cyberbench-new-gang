FROM python:3.12-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends tmux \
    && rm -rf /var/lib/apt/lists/*

RUN python -m pip install --no-cache-dir asciinema

WORKDIR /app
CMD ["sleep", "infinity"]
