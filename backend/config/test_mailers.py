"""MAILERS configuration (US5) - step 14 bug found by the Docker stack.

Django 6.1 sends mail through the ``MAILERS`` setting and raises
``InvalidMailer`` when an option is handed to a backend that does not
accept it: passing the SMTP options (host, port, ...) to the default
console backend crashed every task ``emails.tasks.send_email_task`` in the
container.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent.parent

CONSOLE = "django.core.mail.backends.console.EmailBackend"
SMTP = "django.core.mail.backends.smtp.EmailBackend"
LOC_MEM = "django.core.mail.backends.locmem.EmailBackend"


def _settings_output(code: str, **env: str) -> str:
    result = subprocess.run(
        [sys.executable, "-c", code],
        cwd=BACKEND_DIR,
        env={**os.environ, **env},
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    return result.stdout


def _print_mailers() -> str:
    return (
        "import os; os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings');"
        "import config.settings as s;"
        "print('BACKEND=%s' % s.MAILERS['default']['BACKEND']);"
        "print('OPTIONS=%s' % sorted(s.MAILERS['default']['OPTIONS']));"
    )


def test_console_backend_gets_no_smtp_option():
    """US5: the default backend must not receive options it cannot accept."""
    out = _settings_output(_print_mailers(), EMAIL_BACKEND=CONSOLE)
    assert f"BACKEND={CONSOLE}" in out
    assert "OPTIONS=[]" in out


def test_locmem_backend_gets_no_smtp_option():
    """US5: same rule for the backend the test suite uses."""
    out = _settings_output(_print_mailers(), EMAIL_BACKEND=LOC_MEM)
    assert f"BACKEND={LOC_MEM}" in out
    assert "OPTIONS=[]" in out


def test_smtp_backend_keeps_the_connection_options():
    """US5: the SMTP backend still reads the classic EMAIL_* env keys."""
    out = _settings_output(
        _print_mailers(),
        EMAIL_BACKEND=SMTP,
        EMAIL_HOST="smtp.example.org",
        EMAIL_PORT="2525",
        EMAIL_HOST_USER="mailer",
        EMAIL_HOST_PASSWORD="s3cr3t",
        EMAIL_USE_TLS="False",
    )
    assert f"BACKEND={SMTP}" in out
    for option in ("host", "password", "port", "use_tls", "username"):
        assert option in out.split("OPTIONS=[", 1)[1].rstrip("]")


def test_sending_mail_through_the_real_settings_does_not_raise():
    """US5: regression of the InvalidMailer crash seen in the container."""
    code = (
        "import os; os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings');"
        "import django; django.setup();"
        "from django.core.mail import send_mail;"
        "send_mail('subject', 'body', None, ['someone@example.org'], fail_silently=False);"
        "print('SENT')"
    )
    out = _settings_output(code, EMAIL_BACKEND=CONSOLE)
    assert "SENT" in out
