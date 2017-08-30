# Copyright 2017 The Forseti Security Authors. All rights reserved.
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
"""Fake service account key file."""

FAKE_KEYFILE = b"""
{
  "type": "service_account",
  "client_id": "id123",
  "client_email": "foo@bar.com",
  "private_key_id": "pkid456",
  "private_key": "s3kr3tz"
}
"""

FAKE_REQUIRED_SCOPES = frozenset([
    'https://www.googleapis.com/auth/admin.directory.group.readonly'
])
