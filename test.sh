#!/bin/bash
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

# Uses test_versions.txt and Python virtualenvs to run the library tests
# against multiple versions of Django and Django Rest Framework

set -e
#set -x

# Check for virtualenv
if [ -z "`which virtualenv 2> /dev/null`" ] ; then
    echo "virtualenv not available"
    exit 1
fi

if [ -d bin/ ] ; then
    echo "virtualenv already exists, cannot continue"
    exit 1
fi

while read line ; do
    if [[ $line == \#* ]] ; then
        continue
    fi

    django="`echo $line | cut -d' ' -f1`"
    drf="`echo $line | cut -d' ' -f2`"

    echo "Django $django    DRF $drf"

    # TODO set python version
    virtualenv . --always-copy
    source bin/activate

    # Need to manually install our custom django-oidc and drf-oidc-auth
    # because setuptools doesn't support PEP 508 yet
    pip install Django==$django \
                djangorestframework==$drf \
                git+http://github.com/jhuapl-boss/django-oidc.git\#egg=django-oidc \
                git+http://github.com/jhuapl-boss/drf-oidc-auth.git\#egg=drf-oidc-auth

    python setup.py test > test_results_${django}_${drf}.txt 2>&1

    deactivate
    rm -r bin/
    rm -r include/
    rm -r lib/
    rm pip-selfcheck.json
done < test_versions.txt
