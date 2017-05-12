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

"""Wrapper for SQL API client."""


from httplib2 import HttpLib2Error

from google.cloud.security.common.gcp_api import _base_client
from google.cloud.security.common.gcp_api import errors as api_errors
from google.cloud.security.common.util import log_util
from googleapiclient.errors import HttpError

LOGGER = log_util.get_logger(__name__)


class CloudsqlClient(_base_client.BaseClient):
    """CloudSQL Client."""

    API_NAME = 'sqladmin'

    def __init__(self, credentials=None):
        super(CloudsqlClient, self).__init__(
            credentials=credentials, api_name=self.API_NAME)

    def get_instances(self, project_id):
        """Gets all CloudSQL instances for a project.

        Args:
            project_id: The project id for a GCP project.

        Returns:
            {
              "kind": "storage#buckets",
              "nextPageToken": string,
              "items": [
                buckets Resource
              ]
            }
        """
        cloudsql_service_api = self.service.instances()
        try:
            instances_request = cloudsql_service_api.list(project=project_id)
            instances = instances_request.execute()
            return instances
        except (HttpError, HttpLib2Error) as e:
            LOGGER.error(api_errors.ApiExecutionError(project_id, e))
            # TODO: pass in "buckets" as resource_name variable
            raise api_errors.ApiExecutionError('instances', e)
