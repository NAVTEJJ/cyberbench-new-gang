FROM --platform=linux/amd64 gcc:14-bookworm

RUN apt-get update     && apt-get install -y --no-install-recommends python3 tmux python3-pip     && rm -rf /var/lib/apt/lists/*     && python3 -m pip install --no-cache-dir --break-system-packages asciinema pwntools>=4.14

WORKDIR /app
CMD ["sleep", "infinity"]
