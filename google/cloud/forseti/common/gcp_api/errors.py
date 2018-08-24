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

"""API errors."""

from google.cloud.forseti.common.util import logger

LOGGER = logger.get_logger(__name__)

API_EXECUTION_ERROR_ARG_FORMAT = '{}, {} = {},'


# {Resource}, {Identifier_key} = {Identifier_value},


class Error(Exception):
    """Base Error class."""


class ApiExecutionError(Error):
    """Error for API executions."""

    CUSTOM_ERROR_MESSAGE = (
        'GCP API Error: unable to get {0} from GCP:\n{1}\n{2}')

    def __init__(self, resource_name, e,
                 resource_key=None, resource_value=None):
        """Initialize.

        Args:
            resource_name (str): The resource name.
            e (Exception): The exception.
            resource_key (str): optional, The resource identifier.
            resource_value (str): optional, Value of the resource identifier.
        """
        if resource_key and resource_value:
            resource_name = API_EXECUTION_ERROR_ARG_FORMAT.format(
                resource_name, resource_key, resource_value)
        super(ApiExecutionError, self).__init__(
            self.CUSTOM_ERROR_MESSAGE.format(
                resource_name, e, e.content.decode('utf-8')))
        self.http_error = e


class ApiNotEnabledError(Error):
    """The requested API is not enabled on this project."""

    CUSTOM_ERROR_MESSAGE = ('GCP API Error; API not enabled, turn it on at '
                            '{0}:\n{1}')

    def __init__(self, error_url, e):
        """Initialize.

        Args:
            error_url (str): The error url.
            e (Exception): The exception.
        """
        super(ApiNotEnabledError, self).__init__(
            self.CUSTOM_ERROR_MESSAGE.format(error_url, e))
        self.http_error = e


class OperationTimeoutError(Error):
    """Operation timed out before completing."""

    CUSTOM_ERROR_MESSAGE = ('GCP operation on project {0} timed out before '
                            'completing, Operation name: {1}')

    def __init__(self, project_id, operation):
        """Initialize.

        Args:
            project_id (str): The project id the operation was for.
            operation (dict): The last Operation resource returned from the
                API server.
        """
        super(OperationTimeoutError, self).__init__(
            self.CUSTOM_ERROR_MESSAGE.format(project_id, operation.get('name')))
        self.project_id = project_id
        self.operation = operation


class ApiInitializationError(Error):
    """Error initializing the API."""


class InvalidBucketPathError(Error):
    """Invalid GCS bucket path."""


class UnsupportedApiError(Error):
    """Error for unsupported API."""


class UnsupportedApiVersionError(Error):
    """Error for unsupported API version."""


class PaginationNotSupportedError(Error):
    """Paged Query was issued against an API that does not support paging."""
