import pytest
from django.contrib.auth import get_user_model
from django.core.cache import cache
from rest_framework.test import APIClient

User = get_user_model()
PASSWORD = "StrongPass!234"


@pytest.fixture(autouse=True)
def _fast_hasher(settings):
    settings.PASSWORD_HASHERS = ["django.contrib.auth.hashers.MD5PasswordHasher"]


@pytest.fixture(autouse=True)
def _clear_throttle_cache():
    """Step 8d: every test starts with empty DRF throttle counters."""
    cache.clear()
    yield
    cache.clear()


@pytest.fixture(autouse=True)
def _celery_eager(settings):
    """Step 6: run Celery tasks synchronously in tests (CELERY_TASK_ALWAYS_EAGER).

    Both Django settings and celery app.conf are set: celery caches its
    configuration on first access, so the app.conf assignment is the one
    the worker code actually reads.
    """
    settings.CELERY_TASK_ALWAYS_EAGER = True
    settings.CELERY_TASK_EAGER_PROPAGATES_EXCEPTIONS = True
    from config.celery import app as celery_app

    celery_app.conf.task_always_eager = True
    celery_app.conf.task_eager_propagates = True
    yield
    celery_app.conf.task_always_eager = False
    celery_app.conf.task_eager_propagates = False


@pytest.fixture
def api_client():
    return APIClient()


@pytest.fixture
def make_user(db):
    def _make(email="user@example.com", password=PASSWORD, role="end_user", **extra):
        return User.objects.create_user(email=email, password=password, role=role, **extra)
    return _make


@pytest.fixture
def viewer(make_user):
    return make_user(email="viewer@example.com", role="end_user")


@pytest.fixture
def analyst(make_user):
    return make_user(email="analyst@example.com", role="analyst")


@pytest.fixture
def admin(make_user):
    return make_user(email="admin@example.com", role="admin")


@pytest.fixture
def auth_client(api_client, viewer):
    api_client.force_authenticate(viewer)
    return api_client


@pytest.fixture
def admin_client(api_client, admin):
    api_client.force_authenticate(admin)
    return api_client