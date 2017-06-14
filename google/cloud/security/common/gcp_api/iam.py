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

"""Wrapper for IAM API client."""

from google.cloud.security.common.gcp_api import _base_client


# TODO: The next editor must remove this disable and correct issues.
# pylint: disable=missing-type-doc
# pylint: disable=missing-param-doc


# pylint: disable=too-few-public-methods
class IamClient(_base_client.BaseClient):
    """IAM Client."""

    API_NAME = 'iam'

    def __init__(self, credentials=None):
        super(IamClient, self).__init__(
            credentials=credentials, api_name=self.API_NAME)
