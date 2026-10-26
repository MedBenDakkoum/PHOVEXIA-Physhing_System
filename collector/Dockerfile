# Phish360 collector sandbox (US17 / BR-07).
#
# Multi-stage on the official Playwright image (browsers + deps, non-root
# pwuser). The runtime container never holds datasets, weights or backend
# secrets; the only secret is COLLECTOR_API_KEY, injected at run time.
FROM mcr.microsoft.com/playwright/python:v1.64.1-jammy AS base

ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PLAYWRIGHT_BROWSERS_PATH=/ms-playwright

WORKDIR /srv/collector

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt \
    && python -m playwright install chromium

COPY app ./app

USER pwuser

EXPOSE 8000
CMD ["python", "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]

# One-shot test image: same runtime + pytest stack + fixtures (no publish).
FROM base AS test

USER root
COPY requirements-dev.txt pytest.ini ./
RUN pip install --no-cache-dir -r requirements-dev.txt
COPY tests ./tests
USER pwuser

ENV COLLECTOR_ENV=test \
    COLLECTOR_ALLOW_PRIVATE_HOSTS=testserver \
    COLLECTOR_TIMEOUT_S=5 \
    COLLECTOR_MAX_CONCURRENCY=1

CMD ["python", "-m", "pytest", "-v", "--tb=short", "-p", "no:cacheprovider"]
