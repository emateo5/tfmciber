FROM zaproxy/zap-stable

USER root
ARG CHROME_VERSION=158.0.8127.36
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends ca-certificates curl unzip fonts-liberation libasound2 libatk-bridge2.0-0 libatk1.0-0 libatspi2.0-0 libcups2 libdrm2 libgbm1 libgtk-3-0 libnss3 libxcomposite1 libxdamage1 libxfixes3 libxkbcommon0 libxrandr2 xvfb; \
    mkdir -p /root/.ZAP /tmp/zap-chrome-profile /zap/wrk/artifacts; \
    chmod 0700 /root/.ZAP /tmp/zap-chrome-profile /zap/wrk/artifacts; \
    curl --fail --silent --show-error --location \
        "https://storage.googleapis.com/chrome-for-testing-public/${CHROME_VERSION}/linux64/chrome-linux64.zip" \
        --output /tmp/chrome.zip; \
    curl --fail --silent --show-error --location \
        "https://storage.googleapis.com/chrome-for-testing-public/${CHROME_VERSION}/linux64/chromedriver-linux64.zip" \
        --output /tmp/chromedriver.zip; \
    unzip -q /tmp/chrome.zip -d /opt; \
    unzip -q /tmp/chromedriver.zip -d /opt; \
    ln -sf /opt/chrome-linux64/chrome /usr/bin/chromium; \
    ln -sf /opt/chromedriver-linux64/chromedriver /usr/bin/chromedriver; \
    chmod 0755 /opt/chrome-linux64/chrome /opt/chromedriver-linux64/chromedriver /usr/bin/chromium /usr/bin/chromedriver; \
    rm -f /tmp/chrome.zip /tmp/chromedriver.zip; \
    chromium --no-sandbox --disable-dev-shm-usage --disable-gpu --headless=new --screenshot=/tmp/chrome-build-check.png about:blank; \
    CHROME_MAJOR=$(chromium --version | awk '{print $2}' | cut -d. -f1); \
    DRIVER_MAJOR=$(chromedriver --version | awk '{print $2}' | cut -d. -f1); \
    test "$CHROME_MAJOR" = "$DRIVER_MAJOR"; \
    chromium --version; \
    chromedriver --version; \
    rm -rf /var/lib/apt/lists/*
