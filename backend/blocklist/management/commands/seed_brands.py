"""Seed the protected-brands table from backend/blocklist/seeds/brands.json.

Usage (from backend/, venv active):
    python manage.py seed_brands

Idempotent: a brand whose domain already exists is skipped (not updated), so
the command can be re-run safely after the team adds local brands to the JSON.
The `created_by` FK is required by the model; the command uses (or creates) a
dedicated system account `seed@localhost` with role end_user and an unusable
password - it is NOT a login account.
"""
from __future__ import annotations

import json
from pathlib import Path

from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand, CommandError

from blocklist.models import ProtectedBrand
from blocklist.services import InvalidDomain, normalize_domain

SEEDS_PATH = Path(__file__).resolve().parents[2] / "seeds" / "brands.json"
SEED_USER_EMAIL = "seed@localhost"


class Command(BaseCommand):
    help = "Load protected brands from blocklist/seeds/brands.json (idempotent)."

    def handle(self, *args, **options):
        if not SEEDS_PATH.exists():
            raise CommandError(f"Seeds file not found: {SEEDS_PATH}")
        try:
            rows = json.loads(SEEDS_PATH.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise CommandError(f"Invalid JSON in {SEEDS_PATH}: {exc}") from exc
        if not isinstance(rows, list):
            raise CommandError(f"{SEEDS_PATH} must contain a JSON array.")

        user = get_user_model().objects.filter(email=SEED_USER_EMAIL).first()
        if user is None:
            user = get_user_model().objects.create_user(
                email=SEED_USER_EMAIL,
                password=None,
                role="end_user",
            )
            user.set_unusable_password()
            user.save(update_fields=["password"])

        created = skipped = 0
        for row in rows:
            name = (row.get("name") or "").strip()
            raw_domain = (row.get("domain") or "").strip()
            if not name or not raw_domain:
                self.stderr.write(f"Skipping incomplete row: {row!r}")
                skipped += 1
                continue
            try:
                domain = normalize_domain(raw_domain)
            except InvalidDomain as exc:
                self.stderr.write(f"Skipping invalid domain {raw_domain!r}: {exc}")
                skipped += 1
                continue
            if ProtectedBrand.objects.filter(domain=domain).exists():
                skipped += 1
                continue
            ProtectedBrand.objects.create(
                name=name, domain=domain, is_active=True, created_by=user
            )
            created += 1
        self.stdout.write(
            self.style.SUCCESS(
                f"seed_brands: {created} created, {skipped} skipped "
                f"(file: {SEEDS_PATH.name})."
            )
        )
