FROM golang:1.25-bookworm

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates python3 asciinema tmux \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
CMD ["sleep", "infinity"]
