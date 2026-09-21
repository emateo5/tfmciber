FROM zaproxy/zap-stable

USER root
RUN apt-get update \
    && apt-get install -y --no-install-recommends firefox-esr \
    && rm -rf /var/lib/apt/lists/*
