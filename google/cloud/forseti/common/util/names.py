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

"""Common naming and formatting methods."""

# TODO: Clean these up
SCANNER_OUTPUT_CSV_FMT = 'scanner_output.{}.csv'
OUTPUT_TIMESTAMP_FMT = '%Y%m%dT%H%M%SZ'
TIMESTAMP_FMT = '%Y-%m-%dT%H:%M:%SZ'
VIOLATIONS_JSON_FMT = 'violations.{}.{}.{}.json'
EMAIL_SUMMARY_TIMESTAMP = '%Y %b %d, %H:%M:%S (UTC)'
EMAIL_VIOLATIONS_TIMESTAMP = '%Y-%m-%dT%H:%M:%S.%f'
EMAIL_VIOLATIONS_PRETTY_TIMESTAMP = '%d %B %Y - %H:%M:%S'
INVENTORY_SERVICE_STARTTIME = '%Y-%m-%dT%H:%M:%S.%f'
INVENTORY_SERVICE_BASE_TIMESTAMP = '%Y-%m-%dT%H:%M:%S%z'
