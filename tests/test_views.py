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

# DP NOTE: These are integration tests that test boss-oidc, django-oidc, and
#          drf-oidc-auth. They are included with boss-oidc due to the testing
#          framework that helps test with multiple versions of Django and DRF

import unittest
from unittest.mock import MagicMock, patch, call

from django.conf import settings
from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from rest_framework.exceptions import AuthenticationFailed

import urllib
import requests_mock
import jwt # Using PyJWT as it can produce a signed JWT with minimal effort
import time

SESSION_JWT = jwt.encode({
    # JWT Attributes
    'sub': 'uid',
    'iss': 'https://auth',
    'aud': 'client_id',
    'iat': time.time(),
    'exp': time.time() + 86400, # expires in 1 day

    # Keycloak Attributes
    'preferred_username': 'username',
    'realm_access': {
        'roles': []
    }
}, 'secret').decode('utf8')

BEARER_JWT = jwt.encode({
    # JWT Attributes
    'sub': 'uid',
    'iss': 'https://auth',
    'aud': 'client_id',
    'iat': time.time(),
    'exp': time.time() + 86400, # expires in 1 day

    # Keycloak Attributes
    'preferred_username': 'username',
    'resource_access': {
        'account': {
            'roles': []
        }
    }
}, 'secret').decode('utf8')

WELL_KNOWN_CONFIGURATION = {
    # Taken from the Keycloak /.well-known/openid-configuration file and modified
    "issuer":"https://auth",
    "authorization_endpoint":"https://auth/protocol/openid-connect/auth",
    "token_endpoint":"https://auth/protocol/openid-connect/token",
    "token_introspection_endpoint":"https://auth/protocol/openid-connect/token/introspect",
    "userinfo_endpoint":"https://auth/protocol/openid-connect/userinfo",
    "end_session_endpoint":"https://auth/protocol/openid-connect/logout",
    # Disabled otherwise oic library tries to load certificates
    #"jwks_uri":"https://auth/protocol/openid-connect/certs",
    "grant_types_supported":[
        "authorization_code",
        "implicit",
        "refresh_token",
        "password",
        "client_credentials"
    ],
    "response_types_supported":[
        "code",
        "none",
        "id_token",
        "token",
        "id_token token",
        "code id_token",
        "code token",
        "code id_token token"
    ],
    "subject_types_supported":["public"],
    "id_token_signing_alg_values_supported":["RS256"],
    "response_modes_supported":["query","fragment","form_post"],
}

import bossoidc.settings

class TestViews(TestCase):
    def _configure_settings(self):
        # Setup the configuration as described in the documentation
        bossoidc.settings.configure_oidc('https://auth',
                                         'client_id',
                                         'https://localhost')

        # Copy the values into the active settings
        settings.LOGIN_URL = bossoidc.settings.LOGIN_URL
        settings.LOGOUT_URL = bossoidc.settings.LOGOUT_URL
        settings.OIDC_PROVIDERS = bossoidc.settings.OIDC_PROVIDERS
        settings.OIDC_AUTH = bossoidc.settings.OIDC_AUTH

    @override_settings()
    def test_user_login_session(self):
        self._configure_settings()

        with requests_mock.Mocker() as m:
            # configure Keycloak urls
            token_response = {
                'id_token': SESSION_JWT,
                'access_token': SESSION_JWT,
                'token_type': 'Bearer',
                'expires_in': 3600,
            }
            userinfo_response = {
                'sub': 'uid',
                'preferred_username': 'username',
            }

            m.get('https://auth/.well-known/openid-configuration',
                  json = WELL_KNOWN_CONFIGURATION)
            m.post('https://auth/protocol/openid-connect/token',
                   json = token_response,
                   headers = {'content-type': 'application/json'})
            m.get('https://auth/protocol/openid-connect/userinfo',
                  json = userinfo_response,
                  headers = {'content-type': 'application/json'})

            login_uri = '/openid/openid/KeyCloak?next=/protected/'

            # access protected resource
            resp = self.client.get('/protected/')

            self.assertEqual(resp.status_code, 302)
            self.assertEqual(resp.url, login_uri)

            # redirect to login page
            resp = self.client.get(login_uri)

            url = urllib.parse.urlparse(resp.url)
            qs = urllib.parse.parse_qs(url.query)
            redirect_uri = urllib.parse.unquote(qs['redirect_uri'][0])

            self.assertEqual(resp.status_code, 302)
            self.assertEqual(url.netloc, 'auth')
            self.assertEqual(url.path, '/protocol/openid-connect/auth')
            self.assertEqual(redirect_uri, 'https://localhost/openid/callback/login/')

            # redirected to keycloak
            # Keycloak sets up state for user's session

            # redirect back to application
            callback_url = "/openid/callback/login?code={}&state={}"
            callback_url = callback_url.format('code', qs['state'][0])

            resp = self.client.get(callback_url)

            self.assertEqual(resp.status_code, 302)
            self.assertEqual(resp.url, '/protected/')

            # redirect to protected resource
            resp = self.client.get('/protected/')

            self.assertEqual(resp.status_code, 200)

    @override_settings()
    def test_user_logout(self):
        # login
        self.test_user_login_session()

        # reset the settings, as login will clear them when finished
        self._configure_settings()

        # logout
        resp = self.client.get('/openid/logout')

        url = urllib.parse.urlparse(resp.url)
        qs = urllib.parse.parse_qs(url.query)
        redirect_uri = urllib.parse.unquote(qs['post_logout_redirect_uri'][0])

        self.assertEqual(resp.status_code, 302)
        self.assertEqual(url.netloc, 'auth')
        self.assertEqual(url.path, '/protocol/openid-connect/logout')
        self.assertEqual(redirect_uri, 'https://localhost/openid/callback/logout/')

        # verify
        resp = self.client.get('/protected/')

        login_uri = '/openid/openid/KeyCloak?next=/protected/'
        self.assertEqual(resp.status_code, 302)
        self.assertEqual(resp.url, login_uri)

    @override_settings()
    def test_user_login_token(self):
        self._configure_settings()

        # access protected rest api resource
        resp = self.client.get('/protected-api/')
        self.assertEqual(resp.status_code, 403) # Forbidden

        with requests_mock.Mocker() as m:
            # configure Keycloak urls
            userinfo_response = {
                'sub': 'uid',
                'preferred_username': 'username',
            }

            m.get('https://auth/.well-known/openid-configuration',
                  json = WELL_KNOWN_CONFIGURATION)
            m.get('https://auth/protocol/openid-connect/userinfo',
                  json = userinfo_response,
                  headers = {'content-type': 'application/json'})

            # access protected rest api resource with bearer token
            resp = self.client.get('/protected-api/',
                                   HTTP_AUTHORIZATION = 'Bearer ' + BEARER_JWT)
            self.assertEqual(resp.status_code, 200)

