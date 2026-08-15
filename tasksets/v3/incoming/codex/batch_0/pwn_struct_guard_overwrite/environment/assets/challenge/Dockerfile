FROM python:3.12
RUN apt-get update \
    && apt-get install -y --no-install-recommends gcc libc6-dev \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /srv
COPY vault.c /srv/vault.c
COPY server.py /srv/server.py
RUN gcc -O0 -fno-stack-protector -no-pie -o /srv/vault /srv/vault.c
CMD ["python", "/srv/server.py"]
