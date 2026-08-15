FROM --platform=linux/amd64 ubuntu:24.04@sha256:1e622c5f073b4f6bfad6632f2616c7f59ef256e96fe78bf6a595d1dc4376ac02 AS app

FROM --platform=linux/amd64 ubuntu:24.04@sha256:1e622c5f073b4f6bfad6632f2616c7f59ef256e96fe78bf6a595d1dc4376ac02

RUN apt-get update && apt-get install -y --no-install-recommends socat && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY ./flag.txt /app/flag.txt
COPY ./one_write /app/run

RUN chmod +x /app/run

EXPOSE 1447
CMD ["socat", "TCP-LISTEN:1447,reuseaddr,fork", "EXEC:/app/run,stderr"]
