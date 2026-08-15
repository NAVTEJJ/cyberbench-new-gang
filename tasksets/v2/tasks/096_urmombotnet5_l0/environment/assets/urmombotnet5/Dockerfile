FROM python:3.11-bookworm
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
    && apt-get install -y --no-install-recommends default-libmysqlclient-dev build-essential pkg-config ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir /app
WORKDIR /app
RUN useradd -M -d /app ctf

COPY app /app

RUN chown -R root:ctf /app 
RUN chmod -R 750 /app

RUN pip3 install --no-cache-dir flask PyJWT Flask-MySQLdb

USER ctf

CMD ["python3", "/app/server.py"]
