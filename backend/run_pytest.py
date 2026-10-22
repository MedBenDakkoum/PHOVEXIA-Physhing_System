#!/usr/bin/env python
import os

os.environ['DJANGO_SETTINGS_MODULE'] = 'config.settings'
import sys

sys.argv = ['pytest', '--cov', '--tb=short']
import pytest

sys.exit(pytest.main())
