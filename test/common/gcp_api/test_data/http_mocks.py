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

"""Test data for firewall api responses."""

from googleapiclient import http
from google.cloud.forseti.common.gcp_api import _base_repository


def mock_http_response(response, status='200'):
    """Set the mock response to an http request."""
    http_mock = http.HttpMock()
    http_mock.response_headers = {
        'status': status,
        'content-type': 'application/json',
    }
    http_mock.data = response
    _base_repository.LOCAL_THREAD.http = http_mock


def mock_http_response_sequence(responses):
    """Set the mock response to an http request."""
    http_mock = http.HttpMockSequence(responses)
    _base_repository.LOCAL_THREAD.http = http_mock
