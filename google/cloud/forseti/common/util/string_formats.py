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

"""Common formatting methods."""

# Filename patterns.
CSCC_FINDINGS_FILENAME = 'forseti_findings_{}.json'
SCANNER_OUTPUT_CSV_FMT = 'scanner_output_base.{}.csv'
VIOLATION_JSON_FMT = 'violations.{}.{}.{}.json'
VIOLATION_CSV_FMT = 'violations.{}.{}.{}.csv'
INVENTORY_SUMMARY_JSON_FMT = 'inventory_summary.{}.{}.json'
INVENTORY_SUMMARY_CSV_FMT = 'inventory_summary.{}.{}.csv'

# Timestamps.
# Example: '2018-03-01T21:31:52'
TIMESTAMP_UTC_OFFSET = '%Y-%m-%dT%H:%M:%S%z'

# Example: '2018-03-01T21:32:24.491644'
TIMESTAMP_MICROS = '%Y-%m-%dT%H:%M:%S.%f'

# Example: '2018-03-01T21:33:59Z'
TIMESTAMP_TIMEZONE = '%Y-%m-%dT%H:%M:%SZ'

# Example: '01 March 2018 - 21:38:12'
TIMESTAMP_READABLE = '%d %B %Y - %H:%M:%S'

# Example: '2018-03-01 23:25:59'
TIMESTAMP_MYSQL_DATETIME_FORMAT = '%Y-%m-%d %H:%M:%S'

# Example: '2018 Mar 01, 23:14:55 (UTC)'
TIMESTAMP_READABLE_UTC = '%Y %b %d, %H:%M:%S (UTC)'

# Example: '20180301T213359Z'
TIMESTAMP_TIMEZONE_FILES = '%Y%m%dT%H%M%SZ'

# Defaults to use globally.
DEFAULT_FORSETI_TIMESTAMP = TIMESTAMP_TIMEZONE
DEFAULT_FORSETI_HUMAN_TIMESTAMP = TIMESTAMP_READABLE
DEFAULT_FORSETI_FILE_TIMESTAMP = TIMESTAMP_TIMEZONE_FILES
