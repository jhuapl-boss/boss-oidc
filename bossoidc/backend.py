from django.contrib.auth import get_user_model
from rest_framework.exceptions import AuthenticationFailed
from django.utils.translation import ugettext as _
from djangooidc.backends import OpenIdConnectBackend as DOIDCBackend

def resolve_username(username):
    return username[:30] # Django User username is 30 character limited

def update_user_data(user, token):
    pass

def get_user_by_id(request, id_token):
    User = get_user_model()
    try:
        username = resolve_username(id_token.get('sub'))
        user = User.objects.get_by_natural_key(username)
        update_user_data(user, id_token)
    except User.DoesNotExist:
        msg = _('Invalid Authorization header. User not found.')
        raise AuthenticationFailed(msg)
    return user

class OpenIdConnectBackend(DOIDCBackend):
    def clean_username(self, username)
        return resolve_username(username)

    def authenticate(self, **kwargs):
        # because DOIDCBackend.configure_user() doesn't pass the token data, we
        # have to call it first and then update, instead of replacing configure_user()
        user = super(OpenIdConnectBackend, self).authenticate(**kwargs)
        if user is not None:
            update_user_data(user, kwargs)
        return user