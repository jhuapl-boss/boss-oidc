# Copyright 2019 The Johns Hopkins University Applied Physics Laboratory
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import os
import sys
import django
from django.conf import settings
from django.core.management import call_command

def django_setup():
    if not settings.configured:
        settings.configure(
            DATABASES = {
                'default': {
                    'ENGINE': 'django.db.backends.sqlite3',
                    'NAME': ':memory:',
                }
            },

            INSTALLED_APPS = (
                'django.contrib.contenttypes',
                'django.contrib.auth',
                'django.contrib.sites',
                'django.contrib.sessions',
                'django.contrib.messages',
                'django.contrib.admin.apps.SimpleAdminConfig',
                'django.contrib.staticfiles',
                'bossoidc',
                'djangooidc',
            ),

            MIDDLEWARE_CLASSES = (
                'django.contrib.sessions.middleware.SessionMiddleware',
                'django.middleware.common.CommonMiddleware',
                'django.middleware.csrf.CsrfViewMiddleware',
                'django.contrib.auth.middleware.AuthenticationMiddleware',
                'django.contrib.messages.middleware.MessageMiddleware',
            ),

            ROOT_URLCONF = 'tests.urls',

            ALLOWED_HOSTS = ['testserver'],

            AUTHENTICATION_BACKENDS = [
                'bossoidc.backend.OpenIdConnectBackend',
            ],

            REST_FRAMEWORK = {
                'DEFAULT_AUTHENTICATION_CLASSES': (
                    #'rest_framework.authentication.SessionAuthentication',
                    'oidc_auth.authentication.BearerTokenAuthentication',
                ),
            },
        )

        django.setup()

        call_command('migrate', interactive=False)


def runtests():
    # Move into the parent directory, so results are saved where we want
    curdir = os.path.dirname(os.path.realpath(__file__))
    os.chdir(os.path.join(curdir, '..'))

    # Add parent directory to path so imports work
    sys.path.insert(0, os.path.join(curdir, '..'))

    # Start coverage tracing
    import coverage
    cov = coverage.Coverage(source=["bossoidc"],
                            omit=["bossoidc/admin.py"])
                            # Since admin.py is used by the Django admin pages
                            # there are no tests written for it
    cov.start()

    # Configure Django to support the tests
    # Called after starting coverage to track migration coverage
    django_setup()

    # Find the tests to run
    import unittest
    loader = unittest.TestLoader()
    test_suite = loader.discover('tests', pattern='test_*.py')

    # Run unit tests
    runner = unittest.TextTestRunner()
    runner.run(test_suite)

    # Stop coverage tracing
    cov.stop()
    #cov.save()

    # Display the coverage report
    cov.report()

if __name__ == '__main__':
    runtests()
