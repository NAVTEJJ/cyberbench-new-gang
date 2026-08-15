FROM python:3.12-bookworm

ENV DEBIAN_FRONTEND=noninteractive
ENV PUPPETEER_SKIP_DOWNLOAD=true
ENV PUPPETEER_EXECUTABLE_PATH=/usr/bin/chromium

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
      ca-certificates \
      chromium \
      nodejs \
      npm \
      tini \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /ctf
RUN useradd -M -d /ctf ctf

COPY unhackable2.py /ctf/unhackable2.py
COPY secret_key.txt /ctf/secret_key.txt
COPY templates /ctf/templates
COPY admin_bot.js /ctf/admin_bot.js
COPY start.sh /ctf/start.sh

RUN python -m pip install --no-cache-dir flask \
    && npm install --omit=dev express puppeteer@22.15.0 escape-html \
    && chown -R root:ctf /ctf \
    && chmod -R 750 /ctf \
    && chmod +x /ctf/start.sh

EXPOSE 40007
EXPOSE 40008

ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["bash", "/ctf/start.sh"]
