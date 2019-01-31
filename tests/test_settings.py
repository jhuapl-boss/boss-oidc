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

import unittest
from unittest.mock import MagicMock, patch, call

from django.test import TestCase, override_settings

from bossoidc import settings

# DP TODO: rewrite to have a single check method that will overlay any expected
#          changes to the settings and compair all settings, so that any unexpected
#          changes are caught as well

class TestSettings(TestCase):
    def test_auth_uri(self):
        settings.configure_oidc('auth_uri', '', '')

        setting = settings.OIDC_PROVIDERS['KeyCloak']['srv_discovery_url']
        self.assertEqual(setting, 'auth_uri')

        setting = settings.OIDC_AUTH['OIDC_ENDPOINT']
        self.assertEqual(setting, 'auth_uri')

    def test_client_id(self):
        settings.configure_oidc('', 'client_id', '')

        setting = settings.OIDC_PROVIDERS['KeyCloak']['client_registration']['client_id']
        self.assertEqual(setting, 'client_id')

        setting = settings.OIDC_AUTH['OIDC_AUDIENCES']
        self.assertEqual(setting, ['client_id'])

    def test_public_uri(self):
        settings.configure_oidc('', '', 'http://localhost')

        setting = settings.OIDC_PROVIDERS['KeyCloak']['client_registration']['redirect_uris']
        self.assertEqual(setting, ['http://localhost/openid/callback/login/'])

        setting = settings.OIDC_PROVIDERS['KeyCloak']['client_registration']['post_logout_redirect_uris']
        self.assertEqual(setting, ['http://localhost/openid/callback/logout/'])

    def test_scope(self):
        setting = settings.OIDC_PROVIDERS['KeyCloak']['behaviour']['scope']
        self.assertEqual(setting, ['openid', 'profile', 'email'])

        settings.configure_oidc('', '', '', scope = ['scope'])

        setting = settings.OIDC_PROVIDERS['KeyCloak']['behaviour']['scope']
        self.assertEqual(setting, ['scope'])

    def test_client_secret(self):
        setting = settings.OIDC_PROVIDERS['KeyCloak']['client_registration']
        self.assertNotIn('client_secret', setting)

        settings.configure_oidc('', '', '', client_secret = 'secret')

        setting = settings.OIDC_PROVIDERS['KeyCloak']['client_registration']['client_secret']
        self.assertEqual(setting, 'secret')