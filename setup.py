#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright 2016 The Johns Hopkins University Applied Physics Laboratory
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
from setuptools import setup, find_packages, Command
from setuptools.command.test import test as TestCommand

here = os.path.abspath(os.path.dirname(__file__))
def read(filename):
    with open(os.path.join(here, filename), 'r') as fh:
        return fh.read()

def test_suite():
    """Define the tests that should be run

    Providing a custom test suite so that url.py is not imported,
    as importing it makes django-oidc try to connect to Keycloak

    Returns:
        TestSuite
    """
    import unittest
    loader = unittest.TestLoader()
    suite = loader.discover('tests', pattern='test_*.py')
    return suite

class DjangoMixin(object):
    """Mixin that enables calling Django commands"""

    def django_configure(self):
        """Provide Django a minimal configuration needed for running tests

        This method doesn't set any bossoidc settings
        """
        import django
        from django.conf import settings

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

    def django_migrate(self):
        """Call the Django manage.py migrate command to populate the test database"""
        from django.core.management import call_command

        call_command('migrate', interactive=False)

    def django_makemigrations(self):
        """Call the Django mange.py makemigrations bossoidc command to create
        new migrations
        """
        from django.core.management import call_command

        # Called as interactive because making migrations may require the developer
        # to make decisions (like a default value for a non-null field)
        call_command('makemigrations', 'bossoidc')

# Inspired by the example at https://pytest.org/latest/goodpractises.html
class DjangoTestCommand(TestCommand, DjangoMixin):
    def run_tests(self):
        # Move into the current directory, so results are saved where we want
        curdir = os.path.dirname(os.path.realpath(__file__))
        os.chdir(curdir)

        # Add current directory to path so imports work
        sys.path.insert(0, curdir)

        # Start coverage tracing
        import coverage
        cov = coverage.Coverage(source=["bossoidc"],
                                omit=["bossoidc/admin.py"])
                                # Since admin.py is used by the Django admin pages
                                # there are no tests written for it
        cov.start()

        # Configure Django to support the tests
        # Called after starting coverage to track migration coverage
        self.django_configure()
        self.django_migrate()

        # Run unit tests
        super(DjangoTestCommand, self).run_tests()

        # Stop coverage tracing
        cov.stop()
        #cov.save()

        # Display the coverage report
        cov.report()

class MakeMigrationsCommand(Command, DjangoMixin):
    description = 'Run Django makemigrations'
    user_options = [
        # The format is (long option, short option, description).
    ]

    def initialize_options(self):
        """Abstract method that is required to be overwritten"""

    def finalize_options(self):
        """Abstract method that is required to be overwritten"""

    def run(self):
        self.django_configure()
        self.django_makemigrations()

if __name__ == '__main__':
    setup(
        name='boss-oidc',
        version='1.2.2',
        packages=find_packages(),
        url='https://github.com/jhuapl-boss/boss-oidc',
        license="Apache Software License",
        author='Derek Pryor',
        author_email='Derek.Pryor@jhuapl.edu',
        description='Django Authentication OpenID Connect plugin for the Boss SSO',
        long_description=read('README.md'),
        install_requires = [
            'django<2.0',
            'djangorestframework',
            'oic==1.2.1', # Pinned due to issues with the library
            'pyjwkest>=1.0.0',
            #'django-oidc@http://github.com/jhuapl-boss/django-oidc/archive/master.zip',
            #'drf-oidc-auth@http://github.com/jhuapl-boss/drf-oidc-auth/archive/master.zip'
        ],
        # TODO pin versions of django-oidc / drf-oidc-auth
        # Depdency Links are deprecated but full support for PEP 508 isn't expected
        # until version 10. Commented links in install_requires are the PEP 508 format
        dependency_links = [
            'git+http://github.com/jhuapl-boss/django-oidc.git#egg=django-oidc',
            'git+http://github.com/jhuapl-boss/drf-oidc-auth.git#egg=drf-oidc-auth',
        ],
        tests_require = [
            'coverage',
            'requests_mock',
            'pyjwt',
        ],
        test_suite = 'setup.test_suite',
        classifiers=[
            'Environment :: Web Environment',
            'Development Status :: 5 - Production',
            'Framework :: Django',
            'Intended Audience :: Developers',
            'License :: OSI Approved :: Apache Software License',
            'Operating System :: OS Independent',
            'Natural Language :: English',
            'Programming Language :: Python :: 3',
            'Programming Language :: Python :: 3.5',
        ],
        cmdclass = {
            'test': DjangoTestCommand,
            'makemigrations': MakeMigrationsCommand,
        },
    )
