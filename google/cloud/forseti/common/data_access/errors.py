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

"""Errors related to data access."""


class Error(Exception):
    """Base class for errors."""
    pass


class MySQLError(Error):
    """Error for mysql exceptions."""

    CUSTOM_ERROR_MESSAGE = 'Error with MySQL for {0}:\n{1}'

    def __init__(self, resource_name, e):
        """Initialize.

        Args:
            resource_name (str): The name of the resource.
            e (Exception): The exception.
        """
        super(MySQLError, self).__init__(
            self.CUSTOM_ERROR_MESSAGE.format(resource_name, e))


class NoResultsError(Error):
    """Error for no results found."""
    pass


class CSVFileError(Exception):
    """Error for csv file."""

    CUSTOM_ERROR_MESSAGE = 'Unable to create csv file for {0}:\n{1}'

    def __init__(self, resource_name, e):
        """Initialize.

        Args:
            resource_name (str): The name of the resource.
            e (Exception): The exception.
        """
        super(CSVFileError, self).__init__(
            self.CUSTOM_ERROR_MESSAGE.format(resource_name, e.message))
