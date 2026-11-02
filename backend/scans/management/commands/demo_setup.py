"""One-shot reproducible demo environment (docs/DEMO_RUNBOOK.md).

Refuses to run unless ALLOW_DEMO_SETUP=1 (same guard as ALLOW_SEED for
seed_perf_users): this command provisions known accounts, so it must never
run by accident on a shared environment.

Idempotent (safe to re-run after `docker compose down -v`):
1. creates demo.admin / demo.analyst / demo.user with their REAL roles. The
   password comes from DEMO_PASSWORD in .env; otherwise a random one is
   generated and printed ONCE (never written to any file - .env is
   git-ignored, the command stores nothing). Provisioning happens HERE, on
   the server side: a registration endpoint still always creates END_USER
   and never reads a role from the client (BR-08 / US7).
2. runs seed_brands (protected-brand list used by the brand policy).
3. registers the inference bundle (sync_model_version, reads GET /health) and
   activates it if no TORCH_BUNDLE is active - one call of the BR-11
   activation service, which audits model.activated.
4. runs load_demo_samples for the demo user (golden Phish360 samples,
   inference-only, detection_source=dataset_sample, no quota consumed).
5. guarantees at least 2 scans sit in the analyst review queue (uncertain
   verdicts go there automatically through change_status; DETECTED scans are
   escalated the same way when there are fewer than 2).

Usage (from backend/):
    ALLOW_DEMO_SETUP=1 python manage.py demo_setup
    ALLOW_DEMO_SETUP=1 python manage.py demo_setup --count 5   # smaller demo
"""
from __future__ import annotations

import secrets
from collections import Counter

from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.management import call_command
from django.core.management.base import BaseCommand, CommandError

from controlpanel.models import ModelVersion
from controlpanel.services.model_versions import (
    ModelVersionError,
    activate_model_version,
)

from ...models import Scan
from ...services.workflows import change_status
from .load_demo_samples import load_golden_samples, resolve_samples_dir

User = get_user_model()

DEMO_ACCOUNTS = (
    ("demo.admin@example.org", "admin"),
    ("demo.analyst@example.org", "analyst"),
    ("demo.user@example.org", "end_user"),
)
REVIEW_QUEUE_TARGET = 2


def _random_password() -> str:
    """Valid-looking demo password (3 character classes), printed ONCE only."""
    return f"Demo!{secrets.token_urlsafe(12)}"


class Command(BaseCommand):
    help = (
        "Provision the demo environment (accounts, brands, model version, "
        "golden scans, review queue). Requires ALLOW_DEMO_SETUP=1; idempotent."
    )

    def add_arguments(self, parser):
        parser.add_argument(
            "--count",
            type=int,
            default=20,
            help="Golden samples to load for the demo user (default 20).",
        )

    def handle(self, *args, **options):
        if not settings.ALLOW_DEMO_SETUP:
            raise CommandError(
                "ALLOW_DEMO_SETUP=1 is required: this command provisions "
                "known demo accounts and must not run outside a throwaway "
                "environment (see docs/DEMO_RUNBOOK.md)."
            )
        count = options["count"]

        # --- 1. accounts (server-side provisioning, not a client role) ---
        shared_password = settings.DEMO_PASSWORD or _random_password()
        generated = not bool(settings.DEMO_PASSWORD)
        created: list[str] = []
        skipped: list[str] = []
        accounts: dict[str, User] = {}
        for email, role in DEMO_ACCOUNTS:
            existing = User.objects.filter(email__iexact=email).first()
            if existing is not None:
                accounts[email] = existing
                skipped.append(email)
                continue
            accounts[email] = User.objects.create_user(
                email=email, password=shared_password, role=role
            )
            created.append(email)
        if created:
            if generated:
                self.stdout.write(
                    self.style.WARNING(
                        f"generated demo password (printed ONCE, never stored): "
                        f"{shared_password}"
                    )
                )
            else:
                self.stdout.write("demo password: read from DEMO_PASSWORD in .env.")
        elif skipped and not settings.DEMO_PASSWORD:
            self.stdout.write(
                "accounts already exist; DEMO_PASSWORD is empty so their "
                "password is unchanged (set DEMO_PASSWORD in .env to reset)."
            )

        admin = accounts["demo.admin@example.org"]
        demo_user = accounts["demo.user@example.org"]

        # --- 2. protected brands -----------------------------------------
        call_command("seed_brands")

        # --- 3. model version: register then activate (BR-11) ------------
        try:
            call_command("sync_model_version")
        except CommandError as exc:
            self.stdout.write(
                self.style.WARNING(f"sync_model_version skipped: {exc}")
            )
        active = ModelVersion.objects.filter(
            is_active=True, kind=ModelVersion.Kind.TORCH_BUNDLE
        ).first()
        if active is not None:
            self.stdout.write(
                f"model already active: {active.name} {active.version} (BR-11)."
            )
        else:
            candidate = (
                ModelVersion.objects.filter(kind=ModelVersion.Kind.TORCH_BUNDLE)
                .order_by("-id")
                .first()
            )
            if candidate is None:
                self.stdout.write(
                    self.style.WARNING(
                        "no TORCH_BUNDLE ModelVersion registered (is the "
                        "inference service reachable?). Scans will keep "
                        "detection_source=dataset_sample with an empty model label."
                    )
                )
            else:
                try:
                    activate_model_version(candidate, user=admin)
                except ModelVersionError as exc:
                    raise CommandError(f"activation failed: {exc.detail}") from exc
                self.stdout.write(
                    f"activated {candidate.name} {candidate.version} (BR-11, "
                    "audited as model.activated)."
                )

        # --- 4. golden samples for the demo user --------------------------
        # Same code path as the standalone `load_demo_samples` command (the
        # per-sample lines, mismatch list and summary print right here).
        load_stats = load_golden_samples(
            owner=demo_user,
            samples_dir=resolve_samples_dir(""),
            count=count,
            command=self,
        )

        # --- 5. review queue: at least 2 entries --------------------------
        under_review = Scan.objects.filter(
            owner=demo_user, status=Scan.Status.UNDER_REVIEW
        ).count()
        escalated = 0
        if under_review < REVIEW_QUEUE_TARGET:
            need = REVIEW_QUEUE_TARGET - under_review
            candidates = list(
                Scan.objects.filter(
                    owner=demo_user,
                    status=Scan.Status.DETECTED,
                    detection_source=Scan.DetectionSource.DATASET_SAMPLE,
                )
            )
            # Uncertain verdicts belong in the queue first; top up with any
            # other demo scan when the golden set produced too few of them.
            candidates.sort(key=lambda s: 0 if s.verdict == "uncertain" else 1)
            for scan in candidates[:need]:
                change_status(scan, Scan.Status.UNDER_REVIEW, actor=None)
                escalated += 1

        # --- summary -------------------------------------------------------
        demo_scans = Scan.objects.filter(
            owner=demo_user, detection_source=Scan.DetectionSource.DATASET_SAMPLE
        )
        verdicts = Counter(demo_scans.values_list("verdict", flat=True))
        statuses = Counter(demo_scans.values_list("status", flat=True))
        queue = demo_scans.filter(status=Scan.Status.UNDER_REVIEW).count()

        self.stdout.write("")
        self.stdout.write(self.style.SUCCESS("=== demo_setup summary ==="))
        self.stdout.write(
            f"accounts: {len(created)} created, {len(skipped)} already present "
            f"(admin/analyst/end_user: {', '.join(e for e, _ in DEMO_ACCOUNTS)})"
        )
        self.stdout.write(
            f"password: {'RANDOM printed above, set DEMO_PASSWORD in .env to pin it' if generated else 'from DEMO_PASSWORD in .env'}"
        )
        self.stdout.write(
            f"samples: {load_stats.get('created', 0)} created, "
            f"{load_stats.get('skipped', 0)} skipped, "
            f"{load_stats.get('failed', 0)} failed, "
            f"{load_stats.get('mismatches', 0)} mismatch(es) vs golden_samples.csv "
            "(each mismatch listed above, tolerance 1e-4)"
        )
        self.stdout.write(
            "verdicts: "
            + (", ".join(f"{k}={v}" for k, v in sorted(verdicts.items())) or "none")
        )
        self.stdout.write(
            "statuses: "
            + (", ".join(f"{k}={v}" for k, v in sorted(statuses.items())) or "none")
        )
        self.stdout.write(
            f"review queue: {queue} scan(s) UNDER_REVIEW "
            f"(target {REVIEW_QUEUE_TARGET}, {escalated} escalated this run)."
        )
        self.stdout.write("app: http://127.0.0.1:8080 (docs/DEMO_RUNBOOK.md)")
        # No non-empty return value: BaseCommand.execute would try to write it
        # as text (the stats dict is already printed above).
