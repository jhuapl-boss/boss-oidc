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

from django.conf import settings
from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from rest_framework.exceptions import AuthenticationFailed

from jwkest.jwt import JWT
JWT_HEADERS = {
    'alg': 'RS256',
    'typ': 'JWT',
}

from bossoidc import backend
from bossoidc.models import Keycloak as KeycloakModel

class TestBackend(TestCase):
    def test_check_username(self):
        max_length = backend.get_user_model()._meta.get_field("username").max_length

        username = 'a' * max_length

        backend.check_username(username)

    def test_check_username_too_long(self):
        max_length = backend.get_user_model()._meta.get_field("username").max_length

        username = 'a' * (max_length + 1)

        with self.assertRaises(AuthenticationFailed):
            backend.check_username(username)

    @patch.object(backend, 'UPDATE_USER_DATA_FUNCTION')
    @patch.object(backend, 'LOAD_USER_ROLES_FUNCTION')
    @override_settings()
    def test_get_user_by_id(self, mLoadRoles, mUserData):
        settings.OIDC_AUTH = { 'OIDC_AUDIENCES': ['client_id'] }

        token = {
            'sub': 'uid',
            'preferred_username': 'username',
            'aud': ['client_id'],
            'realm_access': {
                'roles': ['one', 'two', 'three']
            }
        }

        request = MagicMock()
        request.session.get.return_value = JWT().pack([token], JWT_HEADERS)

        user = backend.get_user_by_id(request, token)

        self.assertEqual(user.username, 'username')
        self.assertEqual(user.keycloak.UID, 'uid')
        self.assertEqual(user.first_name, '')
        self.assertEqual(user.last_name, '')
        self.assertEqual(user.email, '')
        self.assertFalse(user.is_staff)
        self.assertFalse(user.is_superuser)

        expected = [call(user, ['one', 'two', 'three'])]
        self.assertEqual(mLoadRoles.mock_calls, expected)

        expected = [call(user, token)]
        self.assertEqual(mUserData.mock_calls, expected)

    @override_settings()
    def test_get_user_by_id_invalid_aud(self):
        settings.OIDC_AUTH = { 'OIDC_AUDIENCES': [] }

        token = {
            'sub': 'uid',
            'preferred_username': 'username',
            'aud': ['client_id']
        }

        request = MagicMock()
        request.session.get.return_value = JWT().pack([token], JWT_HEADERS)

        user = backend.get_user_by_id(request, token)

        self.assertEqual(user, None)

    @override_settings()
    def test_get_user_by_id_invalid_username(self):
        settings.OIDC_AUTH = { 'OIDC_AUDIENCES': ['client_id'] }

        max_length = backend.get_user_model()._meta.get_field("username").max_length
        token = {
            'sub': 'uid',
            'preferred_username': 'a' * (max_length + 1),
            'aud': ['client_id']
        }

        request = MagicMock()
        request.session.get.return_value = JWT().pack([token], JWT_HEADERS)

        with self.assertRaises(AuthenticationFailed):
            backend.get_user_by_id(request, token)

    @override_settings()
    def test_get_user_by_id_user_info(self):
        settings.OIDC_AUTH = { 'OIDC_AUDIENCES': ['client_id'] }

        token = {
            'sub': 'uid',
            'preferred_username': 'username',
            'aud': ['client_id'],
            'first_name': 'first_name', # DP ???: Which values will keycloak actually return?
            'given_name': 'given_name',
            'christian_name': 'christian_name',
            'family_name': 'family_name',
            'last_name': 'last_name',
            'email': 'email'
        }

        request = MagicMock()
        request.session.get.return_value = JWT().pack([token], JWT_HEADERS)

        user = backend.get_user_by_id(request, token)

        self.assertEqual(user.first_name, 'christian_name')
        self.assertEqual(user.last_name, 'last_name')
        self.assertEqual(user.email, 'email')

    @override_settings()
    def test_get_user_by_id_keycloak_user_exists(self):
        settings.OIDC_AUTH = { 'OIDC_AUDIENCES': ['client_id'] }

        UserModel = get_user_model()
        existing_user = UserModel.objects.create(username = 'username')
        KeycloakModel.objects.create(user = existing_user,
                                     UID = 'uid')

        token = {
            'sub': 'uid',
            'preferred_username': 'username',
            'aud': ['client_id'],
        }

        request = MagicMock()
        request.session.get.return_value = JWT().pack([token], JWT_HEADERS)

        user = backend.get_user_by_id(request, token)

        self.assertEqual(user, existing_user)

    @override_settings()
    def test_get_user_by_id_django_user_exists(self):
        settings.OIDC_AUTH = { 'OIDC_AUDIENCES': ['client_id'] }

        UserModel = get_user_model()
        existing_user = UserModel.objects.create(username = 'username')
        # No or incorrect KeycloakModel mapping of this user to the Keycloak UID

        token = {
            'sub': 'uid',
            'preferred_username': 'username',
            'aud': ['client_id'],
        }

        request = MagicMock()
        request.session.get.return_value = JWT().pack([token], JWT_HEADERS)

        user = backend.get_user_by_id(request, token)

        self.assertNotEqual(user, existing_user)

        with self.assertRaises(UserModel.DoesNotExist):
            UserModel.objects.get(id = existing_user.id)

        self.assertEqual(user.username, 'username')
        self.assertEqual(user.keycloak.UID, 'uid')

    @override_settings()
    def test_get_user_by_id_admin_user(self):
        settings.OIDC_AUTH = { 'OIDC_AUDIENCES': ['client_id'] }

        token = {
            'sub': 'uid',
            'preferred_username': 'username',
            'aud': ['client_id'],
            'realm_access': {
                'roles': ['admin']
            }
        }

        request = MagicMock()
        request.session.get.return_value = JWT().pack([token], JWT_HEADERS)

        user = backend.get_user_by_id(request, token)

        self.assertTrue(user.is_staff)
        self.assertFalse(user.is_superuser)

    @override_settings()
    def test_get_user_by_id_superuser_user(self):
        settings.OIDC_AUTH = { 'OIDC_AUDIENCES': ['client_id'] }

        token = {
            'sub': 'uid',
            'preferred_username': 'username',
            'aud': ['client_id'],
            'realm_access': {
                'roles': ['superuser']
            }
        }

        request = MagicMock()
        request.session.get.return_value = JWT().pack([token], JWT_HEADERS)

        user = backend.get_user_by_id(request, token)

        self.assertTrue(user.is_staff)
        self.assertTrue(user.is_superuser)

    def _test_get_roles(self, token, expected):
        roles = backend.get_roles(token)

        self.assertEqual(roles, expected)

    def test_get_roles_password_grant(self):
        token = {
            'realm_access': {
                'roles': ['one', 'two', 'three']
            }
        }

        expected = ['one', 'two', 'three']

        self._test_get_roles(token, expected)

    def test_get_roles_auth_code_grant(self):
        token = {
            'resource_access': {
                'account': {
                    'roles': ['one', 'two', 'three']
                }
            }
        }

        expected = ['one', 'two', 'three']

        self._test_get_roles(token, expected)

    def test_get_roles_client_scope(self):
        token = {
            'aud': '123',
            'resource_access': {
                '123': {
                    'roles': ['one', 'two', 'three']
                }
            }
        }

        expected = ['one', 'two', 'three']

        self._test_get_roles(token, expected)

    def test_get_roles_none_defined(self):
        token = {
        }

        expected = []

        self._test_get_roles(token, expected)

    def test_get_access_token_session(self):
        token = {
            'sub': 'sub',
            'aud': 'aud',
        }
        jwt = JWT().pack([token], JWT_HEADERS)

        request = MagicMock()
        request.session.get.return_value = jwt

        access_token = backend.get_access_token(request)

        self.assertEqual(access_token, token)

    @patch.object(backend, "get_authorization_header")
    def test_get_access_token_header(self, mGetAuthHeader):
        token = {
            'sub': 'sub',
            'aud': 'aud',
        }
        jwt = JWT().pack([token], JWT_HEADERS)
        auth_header = "Bearer " + jwt

        mGetAuthHeader.return_value = auth_header

        request = MagicMock()
        request.session.get.return_value = None

        access_token = backend.get_access_token(request)

        self.assertEqual(access_token, token)

    def test_get_token_audience_str(self):
        token = {
            'aud': 'aud',
        }

        aud = backend.get_token_audience(token)

        self.assertEqual(aud, ['aud'])

    def test_get_token_audience_list(self):
        token = {
            'aud': ['aud'],
        }

        aud = backend.get_token_audience(token)

        self.assertEqual(aud, ['aud'])

    def test_get_token_audience_none_defined(self):
        token = {
        }

        aud = backend.get_token_audience(token)

        self.assertEqual(aud, [])

    @override_settings()
    def test_aud_is_valid(self):
        settings.OIDC_AUTH = {
            'OIDC_AUDIENCES': ['aud'],
        }

        aud = ['aud']

        is_valid = backend.token_audience_is_valid(aud)

        self.assertTrue(is_valid)

    @override_settings()
    def test_aud_is_invalid(self):
        settings.OIDC_AUTH = {
            'OIDC_AUDIENCES': ['aud'],
        }

        aud = ['invalid']

        is_valid = backend.token_audience_is_valid(aud)

        self.assertFalse(is_valid)

    @override_settings()
    def test_aud_is_valid_no_setting(self):
        # These tests don't use the boss-oidc settings module
        # so by default no boss-oidc settings are defined

        aud = ['aud']

        is_valid = backend.token_audience_is_valid(aud)

        self.assertFalse(is_valid)

    @override_settings()
    def test_aud_is_valid_no_setting_2(self):
        settings.OIDC_AUTH = {
        }

        aud = ['aud']

        is_valid = backend.token_audience_is_valid(aud)

        self.assertFalse(is_valid)