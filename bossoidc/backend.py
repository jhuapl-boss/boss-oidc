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
    def clean_username(self, username):
        return resolve_username(username)

    def authenticate(self, **kwargs):
        # because DOIDCBackend.configure_user() doesn't pass the token data, we
        # have to call it first and then update, instead of replacing configure_user()
        user = super(OpenIdConnectBackend, self).authenticate(**kwargs)
        if user is not None:
            update_user_data(user, kwargs)
        return user