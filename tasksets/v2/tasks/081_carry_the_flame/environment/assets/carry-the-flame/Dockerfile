FROM python:3.13-slim-bookworm

RUN apt-get update && apt-get install -y --no-install-recommends socat && rm -rf /var/lib/apt/lists/*
WORKDIR /app

COPY challenge.py /app/challenge.py
COPY flag.txt /app/flag.txt

RUN printf '#!/bin/sh\ncd /app\nexec python3 /app/challenge.py\n' > /app/run && \
    chmod 755 /app/run && \
    chmod 644 /app/flag.txt /app/challenge.py

EXPOSE 5000
CMD ["socat", "TCP-LISTEN:5000,reuseaddr,fork", "EXEC:/app/run,stderr"]
