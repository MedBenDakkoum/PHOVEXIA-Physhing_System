#!/usr/bin/env python
import os
os.environ['DJANGO_SETTINGS_MODULE'] = 'config.settings'
import django
django.setup()
import pytest
import sys
sys.argv = ['pytest', '--cov', '--tb=short', '--override-ini', 'DJANGO_SETTINGS_MODULE=config.settings', '-p', 'django']
exit(pytest.main())