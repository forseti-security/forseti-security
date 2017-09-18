# Copyright 2017 The Forseti Security Authors. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the 'License');
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an 'AS IS' BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Fake AppEngine application data."""

from google.cloud.security.common.util import parser

FAKE_PROJECT_APPLICATIONS_MAP = {
    'project1': {
        u'authDomain': u'gmail.com',
        u'codeBucket': u'staging.project1.appspot.com',
        u'defaultBucket': u'project1.appspot.com',
        u'defaultHostname': u'project1.appspot.com',
        u'gcrDomain': u'us.gcr.io',
        u'id': u'project1',
        u'locationId': u'us-central',
        u'name': u'apps/project1',
        u'servingStatus': u'SERVING'
    }
}

EXPECTED_LOADABLE_APPLICATIONS = [
    {
        'index': u'project1',
        'resource_key': u'apps/project1',
        'resource_type': 'APPENGINE_PIPELINE',
        'resource_data': parser.json_stringify(
            FAKE_PROJECT_APPLICATIONS_MAP['project1'])
    }
]
