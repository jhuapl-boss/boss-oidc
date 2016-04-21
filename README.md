Django Authentication OpenID Connect plugin for the Boss SSO
============================================================

This package configured the django-oidc (jhuapl-boss fork) and drf-oidc-auth Django
authentication plugins for use with the Boss Keycloak authentication server providing
single sign-on (SSO) capability for the larger Boss infrastructure.

While boss-oidc used the OpenID Connect (OIDC) protocol for talking with the Keycloak
Auth server, there may be some Keycloak specific implementation details that are also
captured in the code. Testing with other OIDC providers has not been tested.


Quickstart
----------

Install bossoidc:

```sh
pip install git+https://github.com/jhuapl-boss/boss-oidc.git
```

Configure authentication for Django and Django REST Framework in settings.py:

```py
AUTHENTICATION_BACKENDS = [
    'django.contrib.auth.backends.ModelBackend',
    'bossoidc.backend.OpenIdConnectBackend',
    # ...
]

REST_FRAMEWORK = {
    'DEFAULT_PERMISSION_CLASSES': (
        'rest_framework.permissions.IsAuthenticated',
    ),
    'DEFAULT_AUTHENTICATION_CLASSES': (
        # ...
        'rest_framework.authentication.SessionAuthentication',
        'oidc_auth.authentication.BearerTokenAuthentication',
    ),
}

auth_uri = "https://auth.theboss.io/auth/realms/BOSS"
client_id = "<auth client id>" # Client ID configured in the Auth Server
public_uri = "http://localhost:8000" # The address that the client will be redirected back to
                                     # NOTE: the public uri needs to be configured in the Auth Server
                                     #       as a valid uri to redirect to

from bossoidc.settings import *
configure_oidc(auth_uri, client_id, public_uri)
```

Add the required URLs to the Django project in urls.py:

```py
url(r'openid/', include('djangooidc.urls')),
```

You may now test the authentication by going to (on the development server) http://localhost:8000/openid/login or to any
of your views that requires authentication.


Features
--------

* Ready to use Django authentication backend
* No models stored in database - just some configuration in settings.py to keep it simple
* Fully integrated with Django's internal accounts and permission system
* Support for OpenID Connect Bearer Token Authentication
