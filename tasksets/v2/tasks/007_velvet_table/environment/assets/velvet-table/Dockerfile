FROM --platform=linux/amd64 ubuntu@sha256:cb2af41f42b9c9bc9bcdc7cf1735e3c4b3d95b2137be86fd940373471a34c8b0

RUN apt-get update && apt-get install -y --no-install-recommends socat && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY dist/velvet-table /app/run
COPY flag.txt /app/flag.txt

RUN chmod +x /app/run

EXPOSE 1450
CMD ["socat", "TCP-LISTEN:1450,reuseaddr,fork", "EXEC:/app/run,stderr"]
