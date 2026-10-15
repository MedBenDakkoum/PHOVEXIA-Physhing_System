"""
BR-10 immutability tests for audit entries (audit/models.py + audit/admin.py):

* save() on an existing entry raises ImmutableAuditLogError (row unchanged in DB)
* instance delete() raises ImmutableAuditLogError (row still present)
* queryset update() raises ImmutableAuditLogError (row unchanged in DB)
* queryset delete() raises ImmutableAuditLogError (rows still present)
* the registered Django admin refuses add / change / delete (methods + views 403)

Pure Django + pytest: no network, no external tools.
"""
import pytest
from django.contrib import admin
from django.contrib.admin.sites import AdminSite
from django.contrib.auth import get_user_model
from django.test import RequestFactory

from audit.admin import AuditLogAdmin
from audit.models import AuditLog, ImmutableAuditLogError

pytestmark = pytest.mark.django_db

User = get_user_model()


@pytest.fixture
def entry():
    return AuditLog.objects.create(
        action=AuditLog.Action.REGISTER, user_email="a@b.com"
    )


def test_first_save_is_allowed(entry):
    assert entry.pk is not None


def test_save_on_existing_entry_raises(entry):
    entry.action = AuditLog.Action.LOGIN_SUCCESS
    with pytest.raises(ImmutableAuditLogError):
        entry.save()
    assert AuditLog.objects.get(pk=entry.pk).action == AuditLog.Action.REGISTER


def test_delete_instance_raises(entry):
    with pytest.raises(ImmutableAuditLogError):
        entry.delete()
    assert AuditLog.objects.filter(pk=entry.pk).exists()


def test_queryset_update_raises(entry):
    with pytest.raises(ImmutableAuditLogError):
        AuditLog.objects.filter(pk=entry.pk).update(
            action=AuditLog.Action.LOGIN_FAILED
        )
    assert AuditLog.objects.get(pk=entry.pk).action == AuditLog.Action.REGISTER


def test_queryset_delete_raises(entry):
    with pytest.raises(ImmutableAuditLogError):
        AuditLog.objects.all().delete()
    assert AuditLog.objects.count() == 1


def test_admin_registered_instance_has_no_write_permissions():
    model_admin = admin.site._registry[AuditLog]
    request = RequestFactory().get("/")
    assert model_admin.has_add_permission(request) is False
    assert model_admin.has_change_permission(request) is False
    assert model_admin.has_delete_permission(request, obj=None) is False


def test_admin_fresh_instance_has_no_write_permissions():
    model_admin = AuditLogAdmin(AuditLog, AdminSite())
    request = RequestFactory().get("/")
    assert model_admin.has_add_permission(request) is False
    assert model_admin.has_change_permission(request) is False
    assert model_admin.has_delete_permission(request, obj=None) is False


def test_admin_add_and_delete_views_return_403_for_superuser(client, entry):
    root = User.objects.create_superuser("root@example.com", "password123")
    client.force_login(root)
    assert client.get("/admin/audit/auditlog/add/").status_code == 403
    assert client.get(f"/admin/audit/auditlog/{entry.pk}/delete/").status_code == 403
    assert AuditLog.objects.filter(pk=entry.pk).exists()


def test_admin_change_view_is_read_only_for_superuser(client, entry):
    # Django >= 2.1: has_view_permission is granted by the model "view" perm,
    # so a superuser sees the change form READ-ONLY (consultation only, as
    # intended by audit/admin.py). Saving is still impossible: has_change_permission
    # is False and AuditLog.save() refuses updates (BR-10).
    root = User.objects.create_superuser("root@example.com", "password123")
    client.force_login(root)
    response = client.get(f"/admin/audit/auditlog/{entry.pk}/change/")
    assert response.status_code == 200
    assert AuditLog.objects.get(pk=entry.pk).action == AuditLog.Action.REGISTER
