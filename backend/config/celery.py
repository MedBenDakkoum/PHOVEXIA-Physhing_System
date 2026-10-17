"""Celery application (Step 6).

Loaded by config/__init__.py so `manage.py`, pytest and the worker all see
the same app. Configuration comes from the CELERY_* settings
(config/settings.py): broker = REDIS_URL, JSON serialisation only (no
pickle), soft time limit 60 s / hard 90 s, eager mode in tests.
"""
import os

from celery import Celery

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings")

app = Celery("config")
app.config_from_object("django.conf:settings", namespace="CELERY")
app.autodiscover_tasks()
