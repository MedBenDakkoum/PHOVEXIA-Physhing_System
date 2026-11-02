# Multi-stage production image for the Django API + Celery workers.
#
# Base image: python:3.14.6-slim-bookworm
#   - the development virtualenv runs Python 3.14.6
#     (`phishing_env\Scripts\python.exe --version` -> Python 3.14.6), so the
#     container runs the SAME interpreter version: no 3.12/3.14 drift between
#     dev, tests and production.
#   - "-slim" keeps the image small (no gcc, no docs); "bookworm" (Debian 12)
#     is the stable distribution that ships that Python build.
# Tags are pinned to an exact patch version (no `python:3.14`, no `latest`)
# so a rebuild on another machine cannot silently pick a different Python.
#
# Only requirements.txt is installed: requirements-dev.txt (pytest, ruff,
# bandit, pip-audit, locust, factory-boy) never enters the image.

# ---------------------------------------------------------------- stage 1
FROM python:3.14.6-slim-bookworm AS builder

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1

# Build toolchain: only needed if a wheel is unavailable for cp314 on Linux
# (psycopg2-binary source build needs libpq headers).
RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential libpq-dev \
    && rm -rf /var/lib/apt/lists/*

RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r /tmp/requirements.txt

# ---------------------------------------------------------------- stage 2
FROM python:3.14.6-slim-bookworm AS runtime

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH=/app \
    PATH="/opt/venv/bin:$PATH" \
    DJANGO_SETTINGS_MODULE=config.settings

# libpq5 = runtime shared library of psycopg2 when it was compiled from source.
RUN apt-get update \
    && apt-get install -y --no-install-recommends libpq5 \
    && rm -rf /var/lib/apt/lists/* \
    # Non-root runtime user (no login shell, fixed uid/gid).
    && groupadd --gid 10001 app \
    && useradd --uid 10001 --gid app --create-home --home-dir /home/app \
        --shell /usr/sbin/nologin app

WORKDIR /app

COPY --from=builder /opt/venv /opt/venv
COPY . .

# Entrpoint must be executable; static/models/media are named-volume mount
# points whose ownership is copied into the volume on first use, so
# collectstatic and the demo screenshot writer (running as `app`) can write
# into static_volume / media_volume.
RUN chmod +x /app/deploy/docker-entrypoint.sh \
    && mkdir -p /app/staticfiles /app/models /app/media \
    && chown -R app:app /app

USER app

EXPOSE 8000

# Container health = the public health endpoint of the API. python (not curl):
# the slim image ships neither curl nor wget.
HEALTHCHECK --interval=15s --timeout=5s --start-period=30s --retries=5 \
    CMD python -c "import sys, urllib.request as u; \
sys.exit(0 if u.urlopen('http://127.0.0.1:8000/api/health/', timeout=4).status == 200 else 1)"

# The entrypoint is a GUARD only (env validation, clear startup errors).
# It never runs `manage.py migrate`: migrations are the one-shot `migrate`
# service in docker-compose.yml, never a silent side effect of a worker start.
ENTRYPOINT ["/app/deploy/docker-entrypoint.sh"]
CMD ["gunicorn", "config.wsgi:application", "--bind", "0.0.0.0:8000", \
     "--workers", "3", "--timeout", "60", \
     "--access-logfile", "-", "--error-logfile", "-"]
