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

from django.conf import settings
# bypass the djangooidc provided page and go directly to the keycloak page
LOGIN_URL = "/openid/openid/KeyCloak"
LOGOUT_URL = "/openid/logout"

# DJANGO-OIDC Configuration - Session based SSO authentication
OIDC_PROVIDERS = {
    'KeyCloak': {
        'srv_discovery_url': None,
        'behaviour': {
            'response_type': 'code',
            'scope': ['openid', 'profile', 'email'],
        },
        'client_registration': {
            'client_id': None,
            'redirect_uris': [],
            'post_logout_redirect_uris': [],
        },
    }
}

# DRF-OIDC-AUTH Configuration - Token based authentication
OIDC_AUTH = {
    'OIDC_ENDPOINT': None,
    'OIDC_AUDIENCES': [],
    'OIDC_RESOLVE_USER_FUNCTION': 'bossoidc.backend.get_user_by_id',
    'OIDC_BEARER_TOKEN_EXPIRATION_TIME': 4 * 10, # 4 minutes
}

def configure_oidc(auth_uri, client_id, public_uri, scope=None, client_secret=None):
    global OIDC_PROVIDERS
    OIDC_PROVIDERS['KeyCloak']['srv_discovery_url'] = auth_uri
    OIDC_PROVIDERS['KeyCloak']['client_registration']['client_id'] = client_id
    login_uri = public_uri + '/openid/callback/login/'
    logout_uri = public_uri + '/openid/callback/logout/'
    OIDC_PROVIDERS['KeyCloak']['client_registration']['redirect_uris'] = [login_uri]
    OIDC_PROVIDERS['KeyCloak']['client_registration']['post_logout_redirect_uris'] = [logout_uri]

    # Add a client secret to the config if one is provided:
    if client_secret:
        OIDC_PROVIDERS['KeyCloak']['client_registration']['client_secret'] = client_secret

    if scope:
        # DP NOTE: Scope is only set for django-oidc / session based auth
        #          as it is up to the caller to request the scope when
        #          retrieving the JWT Bearer token that is used by drf-oidc-auth
        OIDC_PROVIDERS['KeyCloak']['behaviour']['scope'] = scope

    global OIDC_AUTH
    OIDC_AUTH['OIDC_ENDPOINT'] = auth_uri
    OIDC_AUTH['OIDC_AUDIENCES'] = [client_id]
