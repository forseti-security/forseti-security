# Copyright 2017 Google Inc.
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

"""Applications data."""

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
        'default_hostname': u'project1.appspot.com',
        'app_id': u'project1',
        'serving_status': u'SERVING',
        'gcr_domain': u'us.gcr.io',
        'location_id': u'us-central',
        'dispatch_rules': '[]',
        'name': u'apps/project1',
        'default_cookie_expiration': None,
        'code_bucket': u'staging.project1.appspot.com',
        'auth_domain': u'gmail.com',
        'project_id': 'project1',
        'iap': '{}',
        'default_bucket': u'project1.appspot.com',
        'raw_application': parser.json_stringify(
            FAKE_PROJECT_APPLICATIONS_MAP['project1'])
    }
]
