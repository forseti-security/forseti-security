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

# Example: '2018-03-01T21:31:52'
TIMESTAMP_UTC_OFFSET = '%Y-%m-%dT%H:%M:%S%z'

# Example: '2018-03-01T21:32:24.491644'
TIMESTAMP_MICROS = '%Y-%m-%dT%H:%M:%S.%f'

# Example: '2018-03-01T21:33:59Z'
TIMESTAMP_TIMEZONE_NAME = '%Y-%m-%dT%H:%M:%SZ'

# Example: '01 March 2018 - 21:38:12'
TIMESTAMP_HUMAN_READABLE = '%d %B %Y - %H:%M:%S'
