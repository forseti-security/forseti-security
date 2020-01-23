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

import inspect
import os

test_rules_path = os.path.dirname(
    os.path.abspath(inspect.getfile(inspect.currentframe())))

ALL_ENABLED = {
    'rules_path': test_rules_path,
    'scanners': [
        {'name': 'bigquery', 'enabled': True},
        {'name': 'bucket_acl', 'enabled': True},
        {'name': 'cloudsql_acl', 'enabled': True},
        {'name': 'iam_policy', 'enabled': True}
    ]}

ALL_DISABLED = {'scanners': []}


CONFIG_VALIDATOR_ENABLED = {
    'rules_path': test_rules_path,
    'scanners': [
        {'name': 'config_validator', 'enabled': True}
    ]}

ONE_ENABLED = {
    'rules_path': test_rules_path,
    'scanners': [
        {'name': 'bigquery', 'enabled': False},
        {'name': 'bucket_acl', 'enabled': False},
        {'name': 'cloudsql_acl', 'enabled': False},
        {'name': 'iam_policy', 'enabled': True}
    ]}

TWO_ENABLED = {
    'rules_path': test_rules_path,
    'scanners': [
        {'name': 'bigquery', 'enabled': False},
        {'name': 'bucket_acl', 'enabled': True},
        {'name': 'cloudsql_acl', 'enabled': False},
        {'name': 'iam_policy', 'enabled': True}
    ]}

NONEXISTENT_ENABLED = {
    'rules_path': test_rules_path,
    'scanners': [
        {'name': 'bigquery', 'enabled': False},
        {'name': 'bucket_acl', 'enabled': True},
        {'name': 'cloudsql_acl', 'enabled': False},
        {'name': 'non_exist_scanner', 'enabled': True}
    ]}

NONEXISTENT_RULES_ENABLED = {
    'rules_path': test_rules_path,
    'scanners': [
        {'name': 'bigquery', 'enabled': False},
        {'name': 'bucket_acl', 'enabled': False},
        {'name': 'cloudsql_acl', 'enabled': False},
        {'name': 'firewall_rule', 'enabled': True},
    ]}

EXTERNAL_PROJECT_ACCESS_ENABLED = {
    'rules_path': test_rules_path,
    'scanners': [
        {'name': 'external_project_access_scanner', 'enabled': True}
    ]}
