#!/usr/bin/env python
# ruff: noqa: I001 - imports intentionally interleaved with django.setup()
import os

os.environ['DJANGO_SETTINGS_MODULE'] = 'config.settings'
import django

django.setup()
import pytest
import sys

sys.argv = ['pytest', '--cov', '--tb=short', '--override-ini', 'DJANGO_SETTINGS_MODULE=config.settings',
'-p', 'django']
sys.exit(pytest.main())
