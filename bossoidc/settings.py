# bypass the djangooidc provided page and go directly to the keycloak page
LOGIN_URL = "/openid/openid/KeyCloak"

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
}

def configure_oidc(auth_uri, client_id, public_uri):
    global OIDC_PROVIDERS
    OIDC_PROVIDERS['KeyCloak']['srv_discovery_url'] = auth_uri
    OIDC_PROVIDERS['KeyCloak']['client_registration']['client_id'] = client_id
    login_uri = public_uri + '/openid/callback/login/'
    logout_uri = public_uri + '/openid/callback/logout/'
    OIDC_PROVIDERS['KeyCloak']['client_registration']['redirect_uris'] = [login_uri]
    OIDC_PROVIDERS['KeyCloak']['client_registration']['post_logout_redirect_uris'] = [logout_uri]

    global OIDC_AUTH
    OIDC_AUTH['OIDC_ENDPOINT'] = auth_uri
    OIDC_AUTH['OIDC_AUDIENCES'] = [client_id]