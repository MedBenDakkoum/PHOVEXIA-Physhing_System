#!/bin/sh
# Startup guard for the production image (Dockerfile ENTRYPOINT).
#
# It validates the environment and fails FAST with a readable message instead
# of letting gunicorn/celery start half-configured. It NEVER runs migrations
# (the one-shot `migrate` service in docker-compose.yml does that), so no
# worker or web process ever applies schema changes silently.
#
# shellcheck shell=sh
set -eu

fail() {
    echo "entrypoint: ERROR: $*" >&2
    exit 1
}

DJANGO_ENV_VALUE="$(printf '%s' "${DJANGO_ENV:-development}" | tr '[:upper:]' '[:lower:]')"

if [ "$DJANGO_ENV_VALUE" = "production" ]; then
    # settings.py enforces the two first ones too; checking them here gives a
    # clear message even for commands that never import Django settings.
    [ -n "${SECRET_KEY:-}" ] \
        || fail "SECRET_KEY is required when DJANGO_ENV=production (set it in backend/.env, never commit it)."
    [ -n "${ALLOWED_HOSTS:-}" ] \
        || fail "ALLOWED_HOSTS is required when DJANGO_ENV=production (comma-separated host names, e.g. 127.0.0.1,example.com)."
    # The full stack runs redis with `--requirepass`, so every backend
    # process must know the password (REDIS_URL embeds it). An empty
    # REDIS_PASSWORD would make the containers start and then fail to
    # reach the broker/cache with a confusing NOAUTH error.
    [ -n "${REDIS_PASSWORD:-}" ] \
        || fail "REDIS_PASSWORD is required by the full Docker profile: redis starts with --requirepass (set it in backend/.env)."
fi

exec "$@"
