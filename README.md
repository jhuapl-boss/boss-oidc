Django Authentication OpenID Connect plugin for the Boss SSO
============================================================

This package configures the mozilla-django-oidc and drf-oidc-auth Django
authentication plugins for use with the Boss Keycloak authentication server providing
single sign-on (SSO) capability for the larger Boss infrastructure.

While boss-oidc used the OpenID Connect (OIDC) protocol for talking with the Keycloak
Auth server, there may be some Keycloak specific implementation details that are also
captured in the code. Testing with other OIDC providers has not been tested.


Quickstart
----------

Install bossoidc:

```sh
pip install mozilla-django-oidc
pip install drf-oidc-auth
pip install git+https://github.com/jhuapl-boss/boss-oidc.git@mozilla#egg=boss-oidc
```

Configure authentication for Django and Django REST Framework in settings.py:

```py
INSTALLED_APPS = [
    # ...
    'bossoidc',
    'djangooidc',
]

AUTHENTICATION_BACKENDS.insert(1, 'bossoidc.backend.OpenIdConnectBackend') 

REST_FRAMEWORK['DEFAULT_AUTHENTICATION_CLASSES'] = (
    'mozilla_django_oidc.contrib.drf.OIDCAuthentication',
    'rest_framework.authentication.SessionAuthentication',
    'boss.authentication.TokenAuthentication',
    'oidc_auth.authentication.BearerTokenAuthentication',
)

# (Optional) A function used to process additional scope values in the token
#            It also provides a helpful hook for each time a user logs in
# Function Args:
#   user (User object): The user that is logging in
#   token (dict): The user's userinfo that was requested from Keycloak and used
#                 to lookup and create or update the user object
UPDATE_USER_DATA = 'path.to.function'

# (Optional) A function used to process a user's roles for the application
#            It also provides a helpful hook for each time a user logs in
# Function Args:
#   user (User object): The user that is logging in
#   roles (list of string): List of the roles the user is currently assigned
LOAD_USER_ROLES = 'path.to.function'

# NOTE: The following two rules are automatically applied to all user account during
#       the login process to allow bootstrapping admin / superuser accounts.
# The user will be assigned Django staff permissions if they have a 'admin' or 'superuser' role in Keycloak
# The user will be assigned Django superuser permissions if they have a 'superuser' role in Keycloak

auth_uri = "https://auth.theboss.io/auth/realms/BOSS"
client_id = "<auth client id>" # Client ID configured in the Auth Server
public_uri = "http://localhost:8000" # The address that the client will be redirected back to
                                     # NOTE: the public uri needs to be configured in the Auth Server
                                     #       as a valid uri to redirect to

OIDC_OP_AUTHORIZATION_ENDPOINT = auth_uri + '/protocol/openid-connect/auth'
OIDC_OP_TOKEN_ENDPOINT = auth_uri + '/protocol/openid-connect/token'
OIDC_OP_USER_ENDPOINT = auth_uri + '/protocol/openid-connect/userinfo'
LOGIN_REDIRECT_URL = public_uri + 'v1/mgmt'
LOGOUT_REDIRECT_URL = auth_uri + '/protocol/openid-connect/logout?redirect_uri=' + public_uri
OIDC_RP_CLIENT_ID = client_id
OIDC_RP_CLIENT_SECRET = ''
OIDC_RP_SCOPES = 'email openid profile'
OIDC_RP_SIGN_ALGO = 'RS256'
OIDC_OP_JWKS_ENDPOINT = auth_uri + '/protocol/openid-connect/certs'

# Fields to look for in the userinfo returned from Keycloak
OIDC_CLAIMS_VERIFICATION = 'preferred_username sub'

# Allow this user to not have an email address during OIDC claims verification.
KEYCLOAK_ADMIN_USER = 'bossadmin'

from bossoidc.settings import *
configure_oidc(auth_uri, client_id, public_uri, scope) # NOTE: scope is optional and can be left out
```

Add the required URLs to the Django project in urls.py:

```py
url(r'openid/', include('djangooidc.urls')),
```

Run the following migration to create the table for storing the Keycloak UID

```sh
$ python manage.py migrate
```

You may now test the authentication by going to (on the development server) http://localhost:8000/openid/login or to any
of your views that requires authentication.


Features
--------

* Ready to use Django authentication backend
* Fully integrated with Django's internal accounts and permission system
* Stores Keycloak UID to improve Keycloak - Django account association
* Support for OpenID Connect Bearer Token Authentication


Contributing
------------

If the bossoidc model is updated or extended to update the Django ORM migrations files run `python setup.py makemigrations` and commit the newly generated files.


Legal
-----


Use or redistribution of the Boss system in source and/or binary forms, with or without modification, are permitted provided that the following conditions are met:

1. Redistributions of source code or binary forms must adhere to the terms and conditions of any applicable software licenses.
2. End-user documentation or notices, whether included as part of a redistribution or disseminated as part of a legal or scientific disclosure (e.g. publication) or advertisement, must include the following acknowledgement:  The Boss software system was designed and developed by the Johns Hopkins University Applied Physics Laboratory (JHU/APL).
3. The names "The Boss", "JHU/APL", "Johns Hopkins University", "Applied Physics Laboratory", "MICrONS", or "IARPA" must not be used to endorse or promote products derived from this software without prior written permission. For written permission, please contact BossAdmin@jhuapl.edu.
4. This source code and library is distributed in the hope that it will be useful, but is provided without any warranty of any kind.

