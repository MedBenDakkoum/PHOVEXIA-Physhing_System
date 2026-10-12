import os
os.environ['DJANGO_SETTINGS_MODULE'] = 'config.settings'
import django
django.setup()
import pytest
pytest.main(['audit/tests.py', '--co', '-q'])