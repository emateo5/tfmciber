FROM zaproxy/zap-stable

USER root
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends firefox-esr; \
    if apt-cache show firefox-geckodriver 2>/dev/null | grep -q '^Package:'; then \
        apt-get install -y --no-install-recommends firefox-geckodriver; \
    elif apt-cache show geckodriver 2>/dev/null | grep -q '^Package:'; then \
        apt-get install -y --no-install-recommends geckodriver; \
    else \
        echo "No se encontró un paquete geckodriver compatible" >&2; \
        exit 1; \
    fi; \
    firefox --version; \
    geckodriver --version; \
    rm -rf /var/lib/apt/lists/*
