FROM node:20-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    wget ca-certificates xz-utils \
    libgtk-3-0 libdbus-glib-1-2 libxt6 libasound2 \
    libx11-xcb1 libxcomposite1 libxdamage1 libxrandr2 libxext6 \
    libpango-1.0-0 libcairo2 libatk1.0-0 libatk-bridge2.0-0 \
    && rm -rf /var/lib/apt/lists/*

ARG TARGETARCH
RUN GECKO_VERSION=v0.36.0 && \
    if [ "$TARGETARCH" = "arm64" ]; then GECKO_ARCH=linux-aarch64; \
    else GECKO_ARCH=linux64; fi && \
    wget -q "https://github.com/mozilla/geckodriver/releases/download/${GECKO_VERSION}/geckodriver-${GECKO_VERSION}-${GECKO_ARCH}.tar.gz" \
    -O /tmp/geckodriver.tar.gz && \
    tar -xzf /tmp/geckodriver.tar.gz -C /usr/local/bin/ && \
    rm /tmp/geckodriver.tar.gz && \
    chmod +x /usr/local/bin/geckodriver

RUN FF_VERSION=148.0 && \
    if [ "$TARGETARCH" = "arm64" ]; then FF_ARCH=linux-aarch64; \
    else FF_ARCH=linux-x86_64; fi && \
    wget -q "https://download-installer.cdn.mozilla.net/pub/firefox/releases/${FF_VERSION}/${FF_ARCH}/en-US/firefox-${FF_VERSION}.tar.xz" \
    -O /tmp/firefox.tar.xz && \
    tar -xf /tmp/firefox.tar.xz -C /opt/ && \
    rm /tmp/firefox.tar.xz && \
    ln -sf /opt/firefox/firefox /usr/local/bin/firefox

ENV FIREFOX_BINARY=/opt/firefox/firefox
ENV MOZ_HEADLESS=1

WORKDIR /app

COPY challenge/dist_ext/ /app/challenge/dist_ext/

COPY bot/package.json bot/package-lock.json* /app/bot/
WORKDIR /app/bot
RUN npm install --production

COPY bot/ /app/bot/

EXPOSE 8080

CMD ["node", "server.js"]
