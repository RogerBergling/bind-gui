# syntax=docker/dockerfile:1

# BIND Workbench is a static single-page application. The image has no API,
# database or write path and runs as an unprivileged user.
FROM python:3.12-alpine

ARG APP_VERSION=dev
ARG IMAGE_TAG=local
ARG GIT_SHA=local
ARG BUILD_DATE=

LABEL org.opencontainers.image.title="BIND Workbench" \
      org.opencontainers.image.description="Local-first BIND DNS configuration editor, analyzer, DNSSEC explorer and multi-file exporter" \
      org.opencontainers.image.version="$APP_VERSION" \
      org.opencontainers.image.revision="$GIT_SHA" \
      org.opencontainers.image.source="https://github.com/RogerBergling/bind-gui" \
      org.opencontainers.image.licenses="MIT" \
      io.bind-workbench.build.version="$APP_VERSION" \
      io.bind-workbench.build.image-tag="$IMAGE_TAG" \
      io.bind-workbench.build.revision="$GIT_SHA" \
      io.bind-workbench.build.date="$BUILD_DATE"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

RUN addgroup -S -g 10001 app \
    && adduser -S -D -H -u 10001 -G app app

COPY --chown=app:app start.py ./start.py
COPY --chown=app:app public ./public

# Bake build metadata into the file read by the home page and footer.
RUN APP_VERSION="$APP_VERSION" IMAGE_TAG="$IMAGE_TAG" GIT_SHA="$GIT_SHA" BUILD_DATE="$BUILD_DATE" \
    python3 -c "import json, os; data = {'version': os.environ['APP_VERSION'], 'imageTag': os.environ['IMAGE_TAG'], 'commit': os.environ['GIT_SHA'], 'buildDate': os.environ.get('BUILD_DATE') or None}; open('public/version.json', 'w', encoding='utf-8').write(json.dumps(data, indent=2) + '\n')" \
    && chown app:app public/version.json

USER 10001:10001

EXPOSE 8005

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD ["python3", "-c", "import urllib.request; urllib.request.build_opener(urllib.request.ProxyHandler({})).open('http://127.0.0.1:8005/', timeout=2).read()"]

CMD ["python3", "start.py", "--host", "0.0.0.0", "--port", "8005", "--no-browser"]
