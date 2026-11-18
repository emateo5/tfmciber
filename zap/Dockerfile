FROM zaproxy/zap-stable

USER root
ARG GECKODRIVER_VERSION=0.36.0
ENV MOZ_DISABLE_CONTENT_SANDBOX=1
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends ca-certificates curl firefox-esr; \
    curl --fail --silent --show-error --location \
        "https://github.com/mozilla/geckodriver/releases/download/v${GECKODRIVER_VERSION}/geckodriver-v${GECKODRIVER_VERSION}-linux64.tar.gz" \
        --output /tmp/geckodriver.tar.gz; \
    tar --extract --gzip --file /tmp/geckodriver.tar.gz --directory /usr/local/bin; \
    chmod 0755 /usr/local/bin/geckodriver; \
    rm -f /tmp/geckodriver.tar.gz; \
    firefox --version; \
    geckodriver --version; \
    rm -rf /var/lib/apt/lists/*
