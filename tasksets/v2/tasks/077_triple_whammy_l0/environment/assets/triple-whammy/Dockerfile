FROM python:3.12-bookworm

ENV DEBIAN_FRONTEND=noninteractive
ENV PUPPETEER_SKIP_DOWNLOAD=true
ENV PUPPETEER_EXECUTABLE_PATH=/usr/bin/chromium

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
      ca-certificates \
      chromium \
      curl \
      nodejs \
      npm \
      procps \
      tini \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /ctf
RUN useradd -M -d /ctf ctf

COPY secret.txt /ctf/secret.txt
COPY flag.txt /ctf/flag.txt
COPY server.py /ctf/server.py
COPY internal.py /ctf/internal.py
COPY start.sh /ctf/start.sh
COPY admin_bot.js /ctf/admin_bot.js

RUN python -m pip install --no-cache-dir flask requests && \
    npm install --omit=dev express puppeteer && \
    chown -R root:ctf /ctf && \
    chmod -R 750 /ctf && \
    chmod +x /ctf/start.sh

EXPOSE 1337
EXPOSE 1336

ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["bash", "/ctf/start.sh"]
