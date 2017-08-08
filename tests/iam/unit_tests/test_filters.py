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
"""Compilation of filters for testing purposes."""

from datetime import datetime
from google.cloud.security.iam.explain.filters import TimeFilter

def create_time_filter(start_from, end_at, list_untimed_resources):
    time_filter = TimeFilter()
    if start_from:
        time_filter.has_start_from = True
        time_filter.start_from = datetime.strptime(start_from,
                                                   '%Y-%m-%dT%H:%M:%S.%fZ')
    if end_at:
        time_filter.has_end_at = True
        time_filter.end_at = datetime.strptime(end_at,
                                               '%Y-%m-%dT%H:%M:%S.%fZ')
    time_filter.list_untimed_resources = list_untimed_resources
    return time_filter
