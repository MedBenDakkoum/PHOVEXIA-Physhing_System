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
    cache.clear()
    yield
    cache.clear()


@pytest.fixture
def api_client():
    return APIClient()


@pytest.fixture
def make_user(db):
    def _make(email="user@example.com", password=PASSWORD, role="viewer", **extra):
        return User.objects.create_user(email=email, password=password, role=role, **extra)
    return _make


@pytest.fixture
def viewer(make_user):
    return make_user(email="viewer@example.com", role="viewer")


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