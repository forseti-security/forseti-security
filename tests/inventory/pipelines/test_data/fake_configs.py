#!/usr/bin/env python
# Copyright 2017 Google Inc.
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

"""Test IAM policies data."""

FAKE_CONFIGS = {
    'inventory_groups': True,
    'groups_service_account_email': 'admin@gserviceaccount.com',
    'service_account_key_file': '/foo/path',
    'domain_super_admin_email': 'admin@foo.com',
    'organization_id': '66666',
    'max_crm_api_calls_per_100_seconds': 400,
    'db_name': 'forseti_security',
    'db_user': 'sqlproxy',
    'db_host': '127.0.0.1',
    'email_sender': 'foo.sender@company.com',
    'email_recipient': 'foo.recipient@company.com',
    'sendgrid_api_key': 'foo_email_key',
}
