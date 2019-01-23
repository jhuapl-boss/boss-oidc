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
from setuptools import setup, find_packages
from setuptools.command.test import test as TestCommand

here = os.path.abspath(os.path.dirname(__file__))
def read(filename):
    with open(os.path.join(here, filename), 'r') as fh:
        return fh.read()

# Inspired by the example at https://pytest.org/latest/goodpractises.html
class XmlTestCommand(TestCommand):
    def finalize_options(self):
        TestCommand.finalize_options(self)
        self.test_args = []

    def run_tests(self):
        from tests.test import runtests
        runtests()

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
        'oic==0.13.0', # Pinned due to issues with the library
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
        'test': XmlTestCommand
    },
)
