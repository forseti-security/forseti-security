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


class Error(Exception):
    """Base Error class."""


class ApiExecutionError(Error):
    """Error for API executions."""

    CUSTOM_ERROR_MESSAGE = 'GCP API Error: unable to get {0} from GCP:\n{1}'

    def __init__(self, resource_name, e):
        """Initialize.

        Args:
            resource_name (str): The resource name.
            e (Exception): The exception.
        """
        super(ApiExecutionError, self).__init__(
            self.CUSTOM_ERROR_MESSAGE.format(resource_name, e))


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

class ApiInitializationError(Error):
    """Error initializing the API."""
    pass

class InvalidBucketPathError(Error):
    """Invalid GCS bucket path."""
    pass


class UnsupportedApiError(Error):
    """Error for unsupported API."""
    pass


class UnsupportedApiVersionError(Error):
    """Error for unsupported API version."""
    pass
