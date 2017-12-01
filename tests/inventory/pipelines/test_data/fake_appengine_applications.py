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

from google.cloud.forseti.common.util import parser

FAKE_PROJECT_APPLICATIONS_MAP = {
    'project1': {
        'authDomain': 'gmail.com',
        'codeBucket': 'staging.project1.appspot.com',
        'defaultBucket': 'project1.appspot.com',
        'defaultHostname': 'project1.appspot.com',
        'gcrDomain': 'us.gcr.io',
        'id': 'project1',
        'locationId': 'us-central',
        'name': 'apps/project1',
        'servingStatus': 'SERVING'
    }
}

EXPECTED_LOADABLE_APPLICATIONS = [
    {
        'default_hostname': 'project1.appspot.com',
        'app_id': 'project1',
        'serving_status': 'SERVING',
        'gcr_domain': 'us.gcr.io',
        'location_id': 'us-central',
        'dispatch_rules': '[]',
        'name': 'apps/project1',
        'default_cookie_expiration': None,
        'code_bucket': 'staging.project1.appspot.com',
        'auth_domain': 'gmail.com',
        'project_id': 'project1',
        'iap': '{}',
        'default_bucket': 'project1.appspot.com',
        'raw_application': parser.json_stringify(
            FAKE_PROJECT_APPLICATIONS_MAP['project1'])
    }
]


FAKE_SERVICES = [
    {
        'split': {'allocations': {'1': 1}},
        'name': 'apps/fakescanner/services/default',
        'id': 'aaaaaa11111'
    }
]

EXPECTED_LOADABLE_SERVICES = [
    {
        'project_id': 'project1',
        'app_id': 'project1',
        'service_id': 'aaaaaa11111',
        'service': parser.json_stringify(FAKE_SERVICES[0])
     }
]

FAKE_VERSIONS = [
    {
        'betaSettings': {
            'source_reference': 'ssh://fake-source-reference'
            },
        'versionUrl': 'https://1-dot-fake.appspot.com',
        'name': 'apps/fakescanner/services/default/versions/1',
        'vm': True,
        'createTime': '2016-10-20T00:40:47Z',
        'servingStatus': 'SERVING',
        'inboundServices': ['INBOUND_SERVICE_WARMUP'],
        'createdBy': 'foo@mygbiz.com',
        'diskUsageBytes': '30227229',
        'automaticScaling': {
            'maxTotalInstances': 20,
            'minTotalInstances': 2,
            'cpuUtilization': {'targetUtilization': 0.5},
            'coolDownPeriod': '120s',
            },
        'runtime': 'java7',
        'id': '1',
        'threadsafe': True,
    }
]     

EXPECTED_LOADABLE_VERSIONS = [
    {
        'project_id': 'project1',
        'app_id': 'project1',
        'service_id': 'aaaaaa11111',
        'version_id': '1',
        'version': parser.json_stringify(FAKE_VERSIONS[0])
     }
]

FAKE_INSTANCES = [
    {
        'name': 'apps/fakescanner/services/default/versions/1/instances/0',
        'id': '0',
        'startTime': '2017-09-09T03:09:44.917Z',
        'qps': 10.704036,
        'vmName': 'gae-default-1-u8qg',
        'availability': 'RESIDENT',
        'vmZoneName': 'us-central1-f',
        'vmStatus': 'RUNNING',
    }, {
        'name': 'apps/fakescanner/services/default/versions/1/instances/1',
        'id': '1',
        'startTime': '2017-09-09T17:47:52.920Z',
        'qps': 5.7435675,
        'vmName': 'gae-default-1-z6c0',
        'availability': 'RESIDENT',
        'vmZoneName': 'us-central1-f',
        'vmStatus': 'RUNNING',
    }
]

EXPECTED_LOADABLE_INSTANCES = [
    {
        'project_id': 'project1',
        'app_id': 'project1',
        'service_id': 'aaaaaa11111',
        'version_id': '1',
        'instance_id': '0',
        'instance': parser.json_stringify(FAKE_INSTANCES[0])
    },
    {
        'project_id': 'project1',
        'app_id': 'project1',
        'service_id': 'aaaaaa11111',
        'version_id': '1',
        'instance_id': '1',
        'instance': parser.json_stringify(FAKE_INSTANCES[1])
     }
]
