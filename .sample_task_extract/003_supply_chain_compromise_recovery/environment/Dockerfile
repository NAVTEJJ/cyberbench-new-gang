FROM python:3.12-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends diffutils file jq tmux \
    && rm -rf /var/lib/apt/lists/*

RUN python -m pip install --no-cache-dir asciinema

WORKDIR /app
COPY assets/ /app/
RUN chmod +x /app/tools/*.py
CMD ["/bin/bash"]
