FROM --platform=linux/amd64 ubuntu:24.04

RUN apt-get update \
    && apt-get install -y --no-install-recommends bash socat tar \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY ./dist.tar.gz /app/dist.tar.gz
RUN tar -xf /app/dist.tar.gz -C /app
COPY d8 /app/d8
COPY wrapper.sh /app/run
COPY ./flag.txt /app/flag.txt
RUN mv /app/flag.txt /app/flag_$(tr -dc A-Za-z0-9 </dev/urandom | head -c 15).txt
RUN chmod +x /app/run /app/d8

EXPOSE 1447
CMD ["socat", "TCP-LISTEN:1447,reuseaddr,fork", "EXEC:/app/run,stderr"]
