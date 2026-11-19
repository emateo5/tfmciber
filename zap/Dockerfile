FROM zaproxy/zap-stable

USER root
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends ca-certificates curl chromium chromium-driver; \
    mkdir -p /root/.ZAP /tmp/zap-chrome-profile /zap/wrk/artifacts; \
    chmod 0700 /root/.ZAP /tmp/zap-chrome-profile /zap/wrk/artifacts; \
    mv /usr/bin/chromium /usr/bin/chromium.real; \
    printf '%s\n' \
        '#!/bin/sh' \
        'exec /usr/bin/chromium.real --no-sandbox --disable-dev-shm-usage --disable-gpu "$@"' \
        > /usr/bin/chromium; \
    chmod 0755 /usr/bin/chromium; \
    chromium --version; \
    chromedriver --version; \
    rm -rf /var/lib/apt/lists/*
