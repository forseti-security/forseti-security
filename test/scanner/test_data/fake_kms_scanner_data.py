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

NON_ROTATED_CRYPTO_KEY_DESTROYED_STATE_DATA = (
                 '{"createTime":"2019-01-22T23:30:18.939244464Z",'
                 '"name":"projects/red2k18-224817/locations/global/keyRings/'
                 'red_key_ring/cryptoKeys/red_key1",'
                 '"nextRotationTime":"2018-07-21T07:00:00Z",'
                 '"primary":{ '
                 '"algorithm":"EC_SIGN_P256_SHA256",'
                 '"createTime":"2018-01-22T23:30:18.939244464Z",'
                 '"generateTie":"2019-01-22T23:30:18.939244464Z",'
                 '"name":"projects/red2k18-224817/locations/global/keyRings/'
                 'red_key_ring/cryptoKeys/red_key1/cryptoKeyVersions/1",'
                 '"protectionLevel":"SOFTWARE",'
                 '"state":"DESTROYED"},'
                 '"purpose":"ENCRYPT_DECRYPT",'
                 '"rotationPeriod":"15552000s",'
                 '"versionTemplate":{'
                 '"algorithm":"GOOGLE_SYMMETRIC_ENCRYPTION",'
                 '"protectionLevel":"SOFTWARE"}}')

PROTECTION_LEVEL_PURPOSE_ALGO_TEST_DATA = (
                 '{"createTime":"2019-01-22T23:30:18.939244464Z",'
                 '"name":"projects/red2k18-224817/locations/global/keyRings/'
                 'red_key_ring/cryptoKeys/red_key1",'
                 '"nextRotationTime":"2019-07-21T07:00:00Z",'
                 '"primary":{ '
                 '"algorithm":"GOOGLE_SYMMETRIC_ENCRYPTION",'
                 '"createTime":"2019-01-22T23:30:18.939244464Z",'
                 '"generateTie":"2019-01-22T23:30:18.939244464Z",'
                 '"name":"projects/red2k18-22487/locations/global/keyRings/'
                 'red_key_ring/cryptoKeys/red_key1/cryptoKeyVersions/1",'
                 '"protectionLevel":"HSM",'
                 '"state":"ENABLED"},'
                 '"purpose":"ASYMMETRIC_SIGN",'
                 '"rotationPeriod":"15552000s",'
                 '"versionTemplate":{'
                 '"algorithm":"GOOGLE_SYMMETRIC_ENCRYPTION",'
                 '"protectionLevel":"SOFTWARE"}}')

KEY_STATE_TEST_DATA = ('{"createTime":"2019-01-22T23:30:18.939244464Z",'
                 '"name":"projects/red2k18-224817/locations/global/keyRings/'
                 'red_key_ring/cryptoKeys/red_key1",'
                 '"nextRotationTime":"2019-07-21T07:00:00Z",'
                 '"primary":{ '
                 '"algorithm":"GOOGLE_SYMMETRIC_ENCRYPTION",'
                 '"createTime":"2019-01-22T23:30:18.939244464Z",'
                 '"generateTie":"2019-01-22T23:30:18.939244464Z",'
                 '"name":"projects/red2k18-22487/locations/global/keyRings/'
                 'red_key_ring/cryptoKeys/red_key1/cryptoKeyVersions/1",'
                 '"protectionLevel":"HSM",'
                 '"state":"ENABLED"},'
                 '"purpose":"ENCRYPT_DECRYPT",'
                 '"rotationPeriod":"15552000s",'
                 '"versionTemplate":{'
                 '"algorithm":"GOOGLE_SYMMETRIC_ENCRYPTION",'
                 '"protectionLevel":"SOFTWARE"}}')

KEY_RING_DATA = ('{"createTime":"2019-01-22T23:29:46.507107968Z",'
                 '"name":"projects/red2k18-224817/locations/global/keyRings/'
                 'red_key_ring",}')

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
