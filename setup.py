#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os

try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup

# allow setup.py to be run from any path
os.chdir(os.path.normpath(os.path.join(os.path.abspath(__file__), os.pardir)))

setup(
    name='boss-oidc',
    version='0.1',
    packages=['bossoidc'],
    url='https://github.com/jhuapl-boss/boss-oidc'
    license="Apache Software License",
    author='Derek Pryor',
    author_email='Derek.Pryor@jhuapl.edu',
    description='Django Authentication OpenID Connect plugin for the Boss SSO',
    install_requires=[
        'django>=1.8',
        'djangorestframework>=2.4.0'
        'oic>=0.76',
        'django-oidc>=0.1.3',
        'drf-oidc-auth>=0.8'
    ]
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
