FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
      ca-certificates \
      gcc \
      libc6-dev \
      gdb \
      strace \
      binutils \
      file \
      python3 \
      tmux \
      curl \
      wget \
    && rm -rf /var/lib/apt/lists/*

COPY target.c /src/target.c

RUN mkdir -p /out && \
    gcc -O1 -g -fsanitize=address -o /out/kvstore_cmd /src/target.c

RUN rm -f /src/target.c

RUN mkdir -p /app /logs/agent /logs/verifier

WORKDIR /app
CMD ["sleep", "infinity"]
