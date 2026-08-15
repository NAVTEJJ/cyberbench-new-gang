FROM ubuntu:22.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
    && apt-get install -y --no-install-recommends python3 tmux asciinema \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /
CMD ["/bin/bash"]
