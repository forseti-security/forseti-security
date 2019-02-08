# Copyright 2018 The Forseti Security Authors. All rights reserved.
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
"""KMS data to be used in the unit tests."""

from google.cloud.forseti.scanner.audit import kms_rules_engine

ROTATED_CRYPTO_KEY_DATA = ('{"createTime":"2019-01-22T23:30:18.939244464Z",'
                 '"name":"projects/red2k18-224817/locations/global/keyRings/'
                 'red_key_ring/cryptoKeys/red_key1",'
                 '"nextRotationTime":"2019-07-21T07:00:00Z",'
                 '"primary":{ '
                 '"algorithm":"GOOGLE_SYMMETRIC_ENCRYPTION",'
                 '"createTime":"2019-01-22T23:30:18.939244464Z",'
                 '"generateTie":"2019-01-22T23:30:18.939244464Z",'
                 '"name":"projects/red2k18-22487/locations/global/keyRings/'
                 'red_key_ring/cryptoKeys/red_key1/cryptoKeyVersions/1",'
                 '"protectionLevel":"SOFTWARE",'
                 '"state":"ENABLED"},'
                 '"purpose":"ENCRYPT_DECRYPT",'
                 '"rotationPeriod":"15552000s",'
                 '"versionTemplate":{'
                 '"algorithm":"GOOGLE_SYMMETRIC_ENCRYPTION",'
                 '"protectionLevel":"SOFTWARE"}}')

NON_ROTATED_CRYPTO_KEY_DATA = ('{"createTime":"2019-01-22T23:30:18.939244464Z",'
                 '"name":"projects/red2k18-224817/locations/global/keyRings/'
                 'red_key_ring/cryptoKeys/red_key1",'
                 '"nextRotationTime":"2018-07-21T07:00:00Z",'
                 '"primary":{ '
                 '"algorithm":"GOOGLE_SYMMETRIC_ENCRYPTION",'
                 '"createTime":"2018-01-22T23:30:18.939244464Z",'
                 '"generateTie":"2019-01-22T23:30:18.939244464Z",'
                 '"name":"projects/red2k18-224817/locations/global/keyRings/'
                 'red_key_ring/cryptoKeys/red_key1/cryptoKeyVersions/1",'
                 '"protectionLevel":"SOFTWARE",'
                 '"state":"ENABLED"},'
                 '"purpose":"ENCRYPT_DECRYPT",'
                 '"rotationPeriod":"15552000s",'
                 '"versionTemplate":{'
                 '"algorithm":"GOOGLE_SYMMETRIC_ENCRYPTION",'
                 '"protectionLevel":"SOFTWARE"}}')

KEY_RING_DATA = ('{"createTime":"2019-01-22T23:29:46.507107968Z",'
            '"name":"projects/red2k18-224817/locations/global/keyRings/red_key_ring",}')

RESOURCE_DATA = ('{"createTime":"2019-01-22T23:30:18.939244464Z",'
                 '"name":"projects/red2k18-224817/locations/global/keyRings/'
                 'red_key_ring/cryptoKeys/red_key1",'
                 '"nextRotationTime":"2019-07-21T07:00:00Z",'
                 '"primary":{ '
                 '"algorithm":"GOOGLE_SYMMETRIC_ENCRYPTION",'
                 '"createTime":"2019-01-22T23:30:18.939244464Z",'
                 '"generateTie":"2019-01-22T23:30:18.939244464Z",'
                 '"name":"projects/red2k18-224817/locations/global/keyRings/'
                 'red_key_ring/cryptoKeys/red_key1/cryptoKeyVersions/1",'
                 '"protectionLevel":"SOFTWARE",'
                 '"state":"ENABLED"},'
                 '"purpose":"ENCRYPT_DECRYPT",'
                 '"rotationPeriod":"15552000s",'
                 '"versionTemplate":{'
                 '"algorithm":"GOOGLE_SYMMETRIC_ENCRYPTION",'
                 '"protectionLevel":"SOFTWARE"}}')

PRIMARY_VERSION = ('"primary":{ '
                 '"algorithm":"GOOGLE_SYMMETRIC_ENCRYPTION",'
                 '"createTime":"2018-01-22T23:30:18.939244464Z",'
                 '"generateTie":"2019-01-22T23:30:18.939244464Z",'
                 '"name":"projects/red2k18-224817/locations/global/keyRings/'
                 'red_key_ring/cryptoKeys/red_key1/cryptoKeyVersions/1",'
                 '"protectionLevel":"SOFTWARE",'
                 '"state":"ENABLED"}')

EXPECTED_VIOLATION = {'resource_id': '12387945269031473611',
                      'resource_type': 'kms_cryptokey',
                      'resource_name': 'organization/660570133860/project/red2k18-224817/kms_keyring/4063867491605246570/kms_cryptokey/12387945269031473611/',
                      'full_name': 'kms_cryptokey',
                      'rule_index': 0,
                      'rule_name': 'All cryptographic keys should be rotated in 100 days',
                      'violation_type': 'CRYPTO_KEY_VIOLATION',
                      'violation_data': 'Key %s was not rotated since %s.',
                      'resource_data': RESOURCE_DATA
                      }
'''
RuleViolation = kms_rules_engine.Rule.RuleViolation

CRYPTO_KEY_VIOLATIONS = [
    RuleViolation(resource_id='12387945269031473611',
                  resource_type='kms_cryptokey',
                  resource_name='organization/660570133860/project/red2k18-224817/kms_keyring/4063867491605246570/kms_cryptokey/12387945269031473611/',
                  full_name='kms_cryptokey',
                  rule_index=0,
                  rule_name='All cryptographic keys should be rotated in 100 days',
                  violation_type='CRYPTO_KEY_VIOLATION',
                  primary_version=PRIMARY_VERSION,
                  next_rotation_time='2019-07-21T07:00:00Z',
                  rotation_period=100,
                  violation_reason='CRYPTO_KEY_VIOLATION',
                  key_creation_time='2019-01-22T23:30:18.939244464Z',
                  version_creation_time='2019-01-22T23:30:18.939244464Z',
                  resource_data=RESOURCE_DATA)
]

GCP_RESOURCES = {

}

'''

RESOURCE_DATA = ('{"createTime":"2019-01-22T23:30:18.939244464Z",'
                 '"name":"projects/red2k18-224817/locations/global/keyRings/'
                 'red_key_ring/cryptoKeys/red_key1",'
                 '"nextRotationTime":"2019-07-21T07:00:00Z",'
                 '"primary":{ '
                 '"algorithm":"GOOGLE_SYMMETRIC_ENCRYPTION",'
                 '"createTime":"2019-01-22T23:30:18.939244464Z",'
                 '"generateTie":"2019-01-22T23:30:18.939244464Z",'
                 '"name":"projects/red2k18-224817/locations/global/keyRings/'
                 'red_key_ring/cryptoKeys/red_key1/cryptoKeyVersions/1",'
                 '"protectionLevel":"SOFTWARE",'
                 '"state":"ENABLED"},'
                 '"purpose":"ENCRYPT_DECRYPT",'
                 '"rotationPeriod":"15552000s",'
                 '"versionTemplate":{'
                 '"algorithm":"GOOGLE_SYMMETRIC_ENCRYPTION",'
                 '"protectionLevel":"SOFTWARE"}}')



MATCHED_VIOLATION = ('[{"rule_name": "All cryptographic keys should be rotated in 100 days",'
                      '"resource_name": "organization/12345/project/foo/kms_keyring/4063867491605246570/kms_cryptokey/12873861500163377322/",' 
                      '"resource_data": {"createTime": "2019-01-22T23:30:18.939244464Z",' 
                      '"name": "projects/red2k18-224817/locations/global/keyRings/red_key_ring/cryptoKeys/red_key1",' 
                      '"nextRotationTime": "2018-07-21T07:00:00Z",'
                      '"primary": {"algorithm": "GOOGLE_SYMMETRIC_ENCRYPTION",'
                      '"createTime": "2018-01-22T23:30:18.939244464Z",'
                      '"generateTie": "2019-01-22T23:30:18.939244464Z",'
                      '"name": "projects/red2k18-224817/locations/global/keyRings/red_key_ring/cryptoKeys/red_key1/cryptoKeyVersions/1",'
                      '"protectionLevel": "SOFTWARE",'
                      '"state": "ENABLED"},'
                      '"purpose": "ENCRYPT_DECRYPT",'
                      '"rotationPeriod": "15552000s",'
                      '"versionTemplate": {"algorithm": "GOOGLE_SYMMETRIC_ENCRYPTION","protectionLevel": "SOFTWARE"}}",'
                      '"full_name": "kms_cryptokey",'
                      '"resource_id": "12873861500163377322",'
                      '"rule_index": 0,'
                      '"violation_type": "CRYPTO_KEY_VIOLATION",'
                      '"violation_data": "Key organization/12345/project/foo/kms_keyring/4063867491605246570/kms_cryptokey/12873861500163377322/ was not rotated since 2018-01-22T23:30:18.939244464Z.",'
                      '"resource_type": "kms_cryptokey"}]'
                  )


MATCHED_VIOLATION = ('{"rule_name": "All cryptographic keys should be rotated in 100 days",'
                      '"resource_name": "organization/12345/project/foo/kms_keyring/4063867491605246570/kms_cryptokey/12873861500163377322/",' 
                      '"resource_data": {"createTime": "2019-01-22T23:30:18.939244464Z",' 
                      '"name": "projects/red2k18-224817/locations/global/keyRings/red_key_ring/cryptoKeys/red_key1",' 
                      '"nextRotationTime": "2018-07-21T07:00:00Z",'
                      '"primary": {"algorithm": "GOOGLE_SYMMETRIC_ENCRYPTION",'
                      '"createTime": "2018-01-22T23:30:18.939244464Z",'
                      '"generateTie": "2019-01-22T23:30:18.939244464Z",'
                      '"name": "projects/red2k18-224817/locations/global/keyRings/red_key_ring/cryptoKeys/red_key1/cryptoKeyVersions/1",'
                      '"protectionLevel": "SOFTWARE",'
                      '"state": "ENABLED"},'
                      '"purpose": "ENCRYPT_DECRYPT",'
                      '"rotationPeriod": "15552000s",'
                      '"versionTemplate": {"algorithm": "GOOGLE_SYMMETRIC_ENCRYPTION","protectionLevel": "SOFTWARE"}},'
                      '"full_name": "kms_cryptokey",'
                      '"resource_id": "12873861500163377322",'
                      '"rule_index": 0,'
                      '"violation_type": "CRYPTO_KEY_VIOLATION",'
                      '"violation_data": "Key organization/12345/project/foo/kms_keyring/4063867491605246570/kms_cryptokey/12873861500163377322/ was not rotated since 2018-01-22T23:30:18.939244464Z.",'
                      '"resource_type": "kms_cryptokey"}'
                     )