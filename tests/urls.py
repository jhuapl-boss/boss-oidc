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

from django.conf.urls import url, include

from django.contrib.auth.decorators import login_required
from django.http.response import HttpResponse

from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated

@login_required
def protected(request):
    return HttpResponse("protected")

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def protected_api(request):
    return Response('protected')

urlpatterns = [
    url(r'^openid/', include('djangooidc.urls')),

    url(r'^protected/', protected, name='protected'),
    url(r'^protected-api/', protected_api, name='protected-api'),
]
