FROM python:3.12-slim
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends socat \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY jail.py run.sh /app/
COPY flag /flag
COPY decoy_flag /app/flag
RUN chmod +x run.sh
EXPOSE 5000
CMD ["socat", "TCP-LISTEN:5000,fork,reuseaddr", "EXEC:./run.sh"]
