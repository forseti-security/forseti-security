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

"""Fake runnable scanners."""

ALL_ENABLED = {'scanners': [
    {'name': 'bigquery', 'enabled': True},
    {'name': 'bucket_acl', 'enabled': True},
    {'name': 'cloudsql_acl', 'enabled': True},
    {'name': 'iam_policy', 'enabled': True}
]}

ALL_DISABLED = {'scanners': []}

ONE_ENABLED = {'scanners': [
    {'name': 'bigquery', 'enabled': False},
    {'name': 'bucket_acl', 'enabled': False},
    {'name': 'cloudsql_acl', 'enabled': False},
    {'name': 'iam_policy', 'enabled': True}
]}

TWO_ENABLED = {'scanners': [
    {'name': 'bigquery', 'enabled': False},
    {'name': 'bucket_acl', 'enabled': True},
    {'name': 'cloudsql_acl', 'enabled': False},
    {'name': 'iam_policy', 'enabled': True}
]}

NONEXISTENT_ENABLED = {'scanners': [
    {'name': 'bigquery', 'enabled': False},
    {'name': 'bucket_acl', 'enabled': True},
    {'name': 'cloudsql_acl', 'enabled': False},
    {'name': 'non_exist_scanner', 'enabled': True}
]}
