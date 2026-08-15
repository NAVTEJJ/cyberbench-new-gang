FROM node:22-bookworm

RUN apt-get update \
    && apt-get install -y --no-install-recommends asciinema tmux \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
CMD ["sleep", "infinity"]
