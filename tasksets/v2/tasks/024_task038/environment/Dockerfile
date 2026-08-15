FROM python:3.11-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends tmux \
    && rm -rf /var/lib/apt/lists/*

RUN python -m pip install --no-cache-dir asciinema

WORKDIR /task
COPY . /task
RUN mkdir -p /src /logs/verifier
