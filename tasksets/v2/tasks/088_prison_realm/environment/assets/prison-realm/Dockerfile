FROM --platform=linux/amd64 ubuntu:22.04

RUN apt-get update && apt-get install -y --no-install-recommends socat && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY ./prison /app/run
COPY ./libc.so.6 /app/libc.so.6
COPY ./ld-linux-x86-64.so.2 /app/ld-linux-x86-64.so.2
COPY ./flag.txt /app/flag.txt

RUN chmod +x /app/run

EXPOSE 1447
CMD ["socat", "TCP-LISTEN:1447,reuseaddr,fork", "EXEC:/app/run,stderr"]
