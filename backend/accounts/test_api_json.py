"""
Tests d'API pilotés par un fichier JSON : accounts/test_data/api_cases.json

Pour ajouter un test, ajoute un scénario dans le JSON : aucun code Python à écrire.
Voir le champ "_help" du JSON pour la syntaxe.
"""
import json
from pathlib import Path

import pytest
from django.contrib.auth import get_user_model
from django.urls import reverse
from rest_framework.test import APIClient

from audit.models import AuditLog

User = get_user_model()
pytestmark = pytest.mark.django_db

DATA_FILE = Path(__file__).parent / "test_data" / "api_cases.json"
DATA = json.loads(DATA_FILE.read_text(encoding="utf-8"))

STEP_KEYS = {"url", "args", "method", "auth", "bearer", "data", "params",
             "remote_addr", "save", "expect", "db", "audit"}
EXPECT_KEYS = {"status", "has_keys", "missing_keys", "json",
               "emails_equal", "contains_emails",
               "results_count", "total_count", "all_match", "first_match"}
DB_KEYS = {"email", "exists", "role", "is_active", "is_staff",
           "first_name", "password_ok"}
AUDIT_KEYS = {"action", "user", "user_email", "target_type", "target_id",
              "target_repr", "ip_address", "metadata", "count"}


def resolve(value, ctx):
    """$nom -> variable sauvegardée ; @cle -> pk de l'utilisateur 'cle'."""
    if isinstance(value, str):
        if value.startswith("$"):
            return ctx["vars"][value[1:]]
        if value.startswith("@"):
            return ctx["users"][value[1:]].pk
        return value
    if isinstance(value, list):
        return [resolve(v, ctx) for v in value]
    if isinstance(value, dict):
        return {k: resolve(v, ctx) for k, v in value.items()}
    return value


def result_items(data):
    return data["results"] if isinstance(data, dict) and "results" in data else data


def dig(obj, path):
    """'results.0.id' -> obj['results'][0]['id']"""
    for part in path.split("."):
        obj = obj[int(part)] if isinstance(obj, list) else obj[part]
    return obj


def check_unknown(keys, allowed, where):
    unknown = set(keys) - allowed
    assert not unknown, f"Clés inconnues dans le JSON ({where}) : {sorted(unknown)}"


def run_expect(expect, response, where):
    check_unknown(expect, EXPECT_KEYS, f"{where}/expect")
    body = response.data
    msg = f"[{where}] statut {response.status_code}, réponse : {body}"

    if "status" in expect:
        assert response.status_code == expect["status"], msg
    for key in expect.get("has_keys", []):
        assert isinstance(body, dict) and key in body, f"clé '{key}' absente. {msg}"
    for key in expect.get("missing_keys", []):
        assert not (isinstance(body, dict) and key in body), f"clé '{key}' présente. {msg}"
    for key, value in expect.get("json", {}).items():
        assert body.get(key) == value, f"'{key}' = {body.get(key)!r}, attendu {value!r}. {msg}"
    if "results_count" in expect:
        assert len(result_items(body)) == expect["results_count"], msg
    if "total_count" in expect:
        assert body["count"] == expect["total_count"], msg
    if "all_match" in expect:
        for item in result_items(body):
            for key, value in expect["all_match"].items():
                assert item[key] == value, f"{key}={item[key]!r} != {value!r}. {msg}"
    if "first_match" in expect:
        first = result_items(body)[0]
        for key, value in expect["first_match"].items():
            assert first[key] == value, f"1er élément : {key}={first[key]!r} != {value!r}. {msg}"
    if "emails_equal" in expect:
        got = sorted(u["email"] for u in result_items(body))
        assert got == sorted(expect["emails_equal"]), msg
    if "contains_emails" in expect:
        got = {u["email"] for u in result_items(body)}
        assert set(expect["contains_emails"]) <= got, msg


def run_db_checks(checks, ctx, where):
    for chk in checks:
        check_unknown(chk, DB_KEYS, f"{where}/db")
        email = resolve(chk["email"], ctx)
        qs = User.objects.filter(email=email)
        should_exist = chk.get("exists", True)
        assert qs.exists() == should_exist, (
            f"[{where}] utilisateur {email} : exists={qs.exists()}, attendu {should_exist}")
        if not should_exist:
            continue
        user = qs.get()
        for field in ("role", "is_active", "is_staff", "first_name"):
            if field in chk:
                assert getattr(user, field) == chk[field], (
                    f"[{where}] {email}.{field} = {getattr(user, field)!r}, attendu {chk[field]!r}")
        if "password_ok" in chk:
            assert user.check_password(resolve(chk["password_ok"], ctx)), (
                f"[{where}] mot de passe incorrect pour {email}")


def run_audit_checks(checks, ctx, where):
    """Chaque vérification compte les entrées du journal qui correspondent (défaut : 1)."""
    for chk in checks:
        check_unknown(chk, AUDIT_KEYS, f"{where}/audit")
        spec = {k: resolve(v, ctx) for k, v in chk.items() if k != "count"}
        expected = chk.get("count", 1)
        found = AuditLog.objects.filter(**spec).count()
        assert found == expected, (
            f"[{where}] journal d'audit {spec} : {found} entrée(s), attendu {expected}. "
            f"Contenu : {list(AuditLog.objects.values('action', 'user_email', 'ip_address'))}")


@pytest.mark.parametrize("case", DATA["cases"], ids=[c["name"] for c in DATA["cases"]])
def test_case(case):
    users = {}
    for key, spec in DATA["users"].items():
        spec = dict(spec)
        users[key] = User.objects.create_user(
            email=spec.pop("email"), password=DATA["password"], **spec)
    ctx = {"users": users, "vars": {"PASSWORD": DATA["password"]}}

    steps = case.get("steps", [case])
    for i, step in enumerate(steps, start=1):
        where = f"{case['name']} / étape {i}"
        check_unknown(set(step) - {"name", "description"}, STEP_KEYS, where)

        client = APIClient()
        if step.get("auth"):
            client.force_authenticate(users[step["auth"]])
        if step.get("bearer"):
            client.credentials(HTTP_AUTHORIZATION=f"Bearer {resolve(step['bearer'], ctx)}")

        url = reverse(step["url"], args=resolve(step.get("args", []), ctx))
        method = step.get("method", "post").lower()
        extra = {"REMOTE_ADDR": step["remote_addr"]} if step.get("remote_addr") else {}
        if method == "get":
            response = client.get(url, resolve(step.get("params", {}), ctx), **extra)
        else:
            response = getattr(client, method)(
                url, resolve(step.get("data"), ctx), format="json", **extra)

        for var, path in step.get("save", {}).items():
            ctx["vars"][var] = dig(response.data, path)

        run_expect(step.get("expect", {}), response, where)
        run_db_checks(step.get("db", []), ctx, where)
        run_audit_checks(step.get("audit", []), ctx, where)