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

from django.contrib import admin
from django.contrib.admin.sites import NotRegistered
from django.contrib.auth import get_user_model
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin

from bossoidc.models import Keycloak


# Define an inline admin descriptor for Keycloak model
# which acts a bit like a singleton
class KeycloakInline(admin.StackedInline):
    model = Keycloak
    can_delete = False
    verbose_name_plural = 'Keycloak'


# Define a new User admin
class UserAdmin(BaseUserAdmin):
    inlines = (KeycloakInline,)


# Re-register UserAdmin
User = get_user_model()
try:
    admin.site.unregister(User)
except NotRegistered:
    pass
finally:
    admin.site.register(User, UserAdmin)
