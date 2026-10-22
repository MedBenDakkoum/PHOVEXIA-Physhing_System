"""Docker stack contract - feature "full Docker stack" (ISO-6.8, ISO-6.6).

These tests read the real Dockerfile, .dockerignore, docker-compose.yml,
deploy/nginx.conf and deploy/docker-entrypoint.sh and pin the security /
portability rules of the feature, so a later edit that silently drops one of
them fails the suite instead of failing in production.
"""

from __future__ import annotations

from pathlib import Path

import yaml

BACKEND_DIR = Path(__file__).resolve().parents[1]


def _read(relative: str) -> str:
    return (BACKEND_DIR / relative).read_text(encoding="utf-8")


def _instructions(content: str) -> str:
    """Code only: comments of the Dockerfile/shell files are excluded."""
    return "\n".join(
        line for line in content.splitlines() if not line.lstrip().startswith("#")
    )


def _compose() -> dict:
    return yaml.safe_load(_read("docker-compose.yml"))


COMPOSE = _compose()
DOCKERFILE = _read("Dockerfile")
NGINX_CONF = _read("deploy/nginx.conf")
ENTRYPOINT = _read("deploy/docker-entrypoint.sh")
# Executable lines only: the comments explain the rules above and are not
# commands (a comment must never be able to satisfy or break a test).
DOCKERFILE_CODE = _instructions(DOCKERFILE)
ENTRYPOINT_CODE = _instructions(ENTRYPOINT)
NGINX_CODE = _instructions(NGINX_CONF)


def test_dev_keeps_only_db_and_redis_and_the_rest_sits_behind_the_full_profile():
    services = COMPOSE["services"]
    for name in ("db", "redis"):
        assert "profiles" not in services[name], f"{name} must start with plain `up`"
    for name in ("migrate", "web", "worker", "beat", "nginx"):
        assert services[name]["profiles"] == ["full"], f"{name} must need --profile full"


def test_every_published_port_is_bound_to_localhost():
    published = [
        port for service in COMPOSE["services"].values() for port in service.get("ports", [])
    ]
    assert published, "at least db, redis and nginx publish a port"
    for port in published:
        assert str(port).startswith("127.0.0.1:"), port


def test_full_profile_needs_the_redis_password_and_forces_one_proxy():
    web_env = COMPOSE["services"]["web"]["environment"]
    assert web_env["NUM_PROXIES"] == "1"
    assert "REDIS_PASSWORD" in web_env["REDIS_URL"]
    redis_command = " ".join(COMPOSE["services"]["redis"]["command"])
    assert "--requirepass" in redis_command
    assert "$$REDIS_PASSWORD" in redis_command
    assert web_env["DJANGO_ENV"] == "production"
    assert web_env["DEBUG"] == "False"


def test_migrations_are_a_one_shot_service_and_never_run_on_worker_start():
    migrate_command = " ".join(COMPOSE["services"]["migrate"]["command"])
    assert "manage.py migrate" in migrate_command
    assert "collectstatic" in migrate_command
    # Neither the image entrypoint nor its CMD ever touches the schema.
    assert "manage.py" not in DOCKERFILE_CODE
    assert "manage.py" not in ENTRYPOINT_CODE
    # Serving processes must not depend on anything that starts them implicitly.
    assert COMPOSE["services"]["migrate"]["restart"] == "no"


def test_nginx_overwrites_forwarded_for_and_serves_the_static_files():
    assert "proxy_set_header X-Forwarded-For $remote_addr;" in NGINX_CODE
    assert "$proxy_add_x_forwarded_for" not in NGINX_CODE
    assert "proxy_set_header X-Forwarded-Proto $scheme;" in NGINX_CODE
    assert "client_max_body_size 1m;" in NGINX_CODE
    assert "gzip on;" in NGINX_CODE
    assert "alias /app/staticfiles/;" in NGINX_CODE
    assert 'add_header X-Content-Type-Options "nosniff" always;' in NGINX_CODE
    assert 'add_header X-Frame-Options "DENY" always;' in NGINX_CODE
    # Docker DNS re-resolution: a stale backend IP must not survive
    # `docker compose up -d` (it would answer 502 until nginx restarts).
    assert "resolver 127.0.0.11 valid=10s ipv6=off;" in NGINX_CODE
    assert "set $backend http://web:8000;" in NGINX_CODE
    assert "upstream" not in NGINX_CODE


def test_volumes_static_and_models_are_shared_and_read_only_where_required():
    web_volumes = COMPOSE["services"]["web"]["volumes"]
    worker_volumes = COMPOSE["services"]["worker"]["volumes"]
    assert "models_volume:/app/models:ro" in web_volumes
    assert "models_volume:/app/models:ro" in worker_volumes
    assert "static_volume:/app/staticfiles" in " ".join(
        COMPOSE["services"]["migrate"]["volumes"]
    )
    assert "static_volume:/app/staticfiles:ro" in COMPOSE["services"]["nginx"]["volumes"]


def test_dockerfile_is_pinned_non_root_and_free_of_dev_dependencies():
    bases = [line for line in DOCKERFILE.splitlines() if line.startswith("FROM")]
    assert bases, "multi-stage build expected"
    for line in bases:
        assert "python:3.14.6-slim-bookworm" in line, line
        assert ":latest" not in line
    assert "USER app" in DOCKERFILE
    assert "PYTHONUNBUFFERED=1" in DOCKERFILE
    assert "HEALTHCHECK" in DOCKERFILE
    assert "gunicorn" in DOCKERFILE
    assert "requirements-dev.txt" not in DOCKERFILE_CODE
    assert "--workers" in DOCKERFILE_CODE


def test_dockerignore_hides_secrets_db_docs_and_test_artifacts():
    ignored = _read(".dockerignore")
    for pattern in (
        ".env",
        "phishing_env/",
        "db.sqlite3",
        "docs/",
        "**/__pycache__/",
        "**/test_*.py",
        "requirements-dev.txt",
        ".pytest_cache/",
        ".coverage",
    ):
        assert pattern in ignored, pattern


def test_entrypoint_is_a_guard_that_fails_fast_in_production():
    assert "SECRET_KEY is required" in ENTRYPOINT
    assert "ALLOWED_HOSTS is required" in ENTRYPOINT
    assert "REDIS_PASSWORD is required" in ENTRYPOINT
    assert 'exec "$@"' in ENTRYPOINT_CODE
    assert "collectstatic" not in ENTRYPOINT_CODE
