"""Create the 20 end-user accounts used by the locust load test.

Usage (from backend/, venv active, ALLOW_SEED=1 set):
    ALLOW_SEED=1 python manage.py seed_perf_users

Refuses to run unless the ALLOW_SEED=1 environment variable is present: this
command creates accounts with a KNOWN password, so it must never run by
accident in a shared/production environment. Accounts are created with
role=end_user (registration always creates END_USER; a load-test bot is a
regular user).

Idempotent: an email that already exists is skipped, so the command can be
re-run (e.g. after `docker compose down -v`) without duplicating rows or
breaking the daily scan quota counters.
"""
from __future__ import annotations

import os

from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand, CommandError

PERF_USER_COUNT = 20
PERF_EMAIL_TEMPLATE = "perf.user{:02d}@example.org"
# Chosen to pass the common "3 of 4 character classes" validators.
PERF_PASSWORD = "PerfUser!2026x"


class Command(BaseCommand):
    help = (
        "Create the 20 perf.userNN@example.org accounts used by the locust "
        "run (requires ALLOW_SEED=1; idempotent)."
    )

    def handle(self, *args, **options):
        if os.getenv("ALLOW_SEED", "").strip() != "1":
            raise CommandError(
                "ALLOW_SEED=1 is required: this command creates accounts with "
                "a known password and must not run outside a throwaway perf "
                "environment."
            )
        user_model = get_user_model()
        created = skipped = 0
        for index in range(1, PERF_USER_COUNT + 1):
            email = PERF_EMAIL_TEMPLATE.format(index)
            if user_model.objects.filter(email=email).exists():
                skipped += 1
                continue
            user_model.objects.create_user(
                email=email,
                password=PERF_PASSWORD,
                role="end_user",
            )
            created += 1
        self.stdout.write(
            self.style.SUCCESS(
                f"seed_perf_users: {created} created, {skipped} skipped, "
                f"{PERF_USER_COUNT} accounts total "
                f"({PERF_EMAIL_TEMPLATE.format(1)} .. "
                f"{PERF_EMAIL_TEMPLATE.format(PERF_USER_COUNT)})."
            )
        )
