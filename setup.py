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

try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup

# allow setup.py to be run from any path
os.chdir(os.path.normpath(os.path.join(os.path.abspath(__file__), os.pardir)))

setup(
    name='boss-oidc',
    version='1.2.1',
    packages=['bossoidc'],
    url='https://github.com/jhuapl-boss/boss-oidc',
    license="Apache Software License",
    author='Derek Pryor',
    author_email='Derek.Pryor@jhuapl.edu',
    description='Django Authentication OpenID Connect plugin for the Boss SSO',
    install_requires=[
        'django>=1.8',
        'djangorestframework>=2.4.0',
        'oic>=0.7.6',
        'django-oidc>=0.1.3',
        'drf-oidc-auth>=0.8'
    ],
    classifiers=[
        'Environment :: Web Environment',
        'Development Status :: 4 - Beta',
        'Framework :: Django',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: Apache Software License',
        'Operating System :: OS Independent',
        'Natural Language :: English',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.5',
    ],
)
