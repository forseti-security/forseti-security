# Copyright 2018 The Forseti Security Authors. All rights reserved.
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

"""Wrapper for Cloud Asset API client."""
import time

from googleapiclient import errors
from httplib2 import HttpLib2Error

from google.cloud.forseti.common.gcp_api import _base_repository
from google.cloud.forseti.common.gcp_api import api_helpers
from google.cloud.forseti.common.gcp_api import errors as api_errors
from google.cloud.forseti.common.gcp_api import repository_mixins
from google.cloud.forseti.common.util import logger

LOGGER = logger.get_logger(__name__)
API_NAME = 'cloudasset'


class CloudAssetRepositoryClient(_base_repository.BaseRepositoryClient):
    """Cloud Asset API Respository."""

    def __init__(self,
                 quota_max_calls=None,
                 quota_period=60.0,
                 use_rate_limiter=True):
        """Constructor.

        Args:
            quota_max_calls (int): Allowed requests per <quota_period> for the
                API.
            quota_period (float): The time period to track requests over.
            use_rate_limiter (bool): Set to false to disable the use of a rate
                limiter for this service.
        """
        if not quota_max_calls:
            use_rate_limiter = False

        self._top_level = None
        self._operations = None

        super(CloudAssetRepositoryClient, self).__init__(
            API_NAME, versions=['v1'],
            quota_max_calls=quota_max_calls,
            quota_period=quota_period,
            use_rate_limiter=use_rate_limiter)

    # Turn off docstrings for properties.
    # pylint: disable=missing-return-doc, missing-return-type-doc
    @property
    def top_level(self):
        """Returns a _CloudAssetV1Repository instance."""
        if not self._top_level:
            self._top_level = self._init_repository(
                _CloudAssetV1Repository)
        return self._top_level

    @property
    def operations(self):
        """Returns a _CloudAssetOperationsRepository instance."""
        if not self._operations:
            self._operations = self._init_repository(
                _CloudAssetOperationsRepository)
        return self._operations
    # pylint: enable=missing-return-doc, missing-return-type-doc


class _CloudAssetV1Repository(
        repository_mixins.ExportAssetsQueryMixin,
        _base_repository.GCPRepository):
    """Implementation of Cloud Asset V1 repository."""

    def __init__(self, **kwargs):
        """Constructor.

        Args:
            **kwargs (dict): The args to pass into GCPRepository.__init__()
        """
        # The top level API methods are rooted under the v1 component in the
        # discovery doc.
        super(_CloudAssetV1Repository, self).__init__(
            component='v1', **kwargs)


class _CloudAssetOperationsRepository(
        repository_mixins.GetQueryMixin,
        _base_repository.GCPRepository):
    """Implementation of Cloud Asset Operations repository."""

    def __init__(self, **kwargs):
        """Constructor.

        Args:
            **kwargs (dict): The args to pass into GCPRepository.__init__()
        """
        super(_CloudAssetOperationsRepository, self).__init__(
            key_field='name', component='operations', **kwargs)


class CloudAssetClient(object):
    """Cloud Asset Client."""

    # Estimation of how long to wait for an async API to complete.
    OPERATION_DELAY_IN_SEC = 5.0

    def __init__(self, global_configs, **kwargs):
        """Initialize.

        Args:
            global_configs (dict): Global configurations.
            **kwargs (dict): The kwargs.
        """
        max_calls, quota_period = api_helpers.get_ratelimiter_config(
            global_configs, API_NAME)

        self.repository = CloudAssetRepositoryClient(
            quota_max_calls=max_calls,
            quota_period=quota_period,
            use_rate_limiter=kwargs.get('use_rate_limiter', True))

    def export_assets(self, parent, destination_object, content_type=None,
                      asset_types=None, blocking=False, timeout=0):
        """Export assets under a parent resource to the destination GCS object.

        Args:
            parent (str): The name of the parent resource to export assests
                under.
            destination_object (str): The GCS path and file name to store the
                results in. The bucket must be in the same project that has the
                Cloud Asset API enabled.
            content_type (str): The specific content type to export, currently
                supports "RESOURCE" and "IAM_POLICY". If not specified only the
                CAI metadata for assets are included.
            asset_types (list): The list of asset types to filter the results
                to, if not specified, exports all assets known to CAI.
            blocking (bool): If true, don't return until the async operation
                completes on the backend or timeout seconds pass.
            timeout (float): If greater than 0 and blocking is True, then raise
                an exception if timeout seconds pass before the operation
                completes.

        Returns:
            dict: Operation status and info.

        Raises:
            ApiExecutionError: Returns if there is an error in the API response.
            OperationTimeoutError: Raised if the operation times out.
            ValueError: Raised on invalid parent resource name.
        """
        if not (parent.startswith('folders/') or
                parent.startswith('organizations/') or
                parent.startswith('projects/')):
            raise ValueError('parent must start with folders/, projects/, or '
                             'organizations/')

        repository = self.repository.top_level
        try:
            results = repository.export_assets(
                parent, destination_object, content_type=content_type,
                asset_types=asset_types)
            if blocking:
                results = self.wait_for_completion(parent, results,
                                                   timeout=timeout)
        except (errors.HttpError, HttpLib2Error) as e:
            LOGGER.error('Error exporting assets for parent %s: %s', parent, e)
            raise api_errors.ApiExecutionError(parent, e)
        except api_errors.OperationTimeoutError as e:
            LOGGER.warn('Timeout exporting assets for parent %s: %s', parent, e)
            raise

        LOGGER.info('Exporting assets for parent %s. Result: %s',
                    parent, results)
        return results

    def get_operation(self, operation_name):
        """Get the Operations Status.

        Args:
            operation_name (str): The name of the operation to get.

        Returns:
            dict: Operation status and info.

        Raises:
            ApiExecutionError: Returns if there is an error in the API response.
            ValueError: Raised on invalid parent resource name.
        """
        if not (operation_name.startswith('folders/') or
                operation_name.startswith('organizations/') or
                operation_name.startswith('projects/')):
            raise ValueError('operation_name must start with folders/, '
                             'projects/, or organizations/')

        repository = self.repository.operations
        try:
            results = repository.get(operation_name)
            LOGGER.debug('Getting the operation status, operation_name = %s, '
                         'results = %s', operation_name, results)
        except (errors.HttpError, HttpLib2Error) as e:
            raise api_errors.ApiExecutionError(operation_name, e)

        return results

    def wait_for_completion(self, parent, operation, timeout=0,
                            initial_delay=None, retry_delay=None):
        """Wait for the operation to complete.

        Args:
            parent (str): The name of the parent resource to export assests
                under.
            operation (dict): The operation response from an API call.
            timeout (float): The maximum time to wait for the operation to
                complete.
            initial_delay (float): The time to wait before first checking if the
                API has completed. If None then the default value, configured as
                CloudAssetClient.OPERATION_DELAY_IN_SEC, is used.
            retry_delay (float): The time to wait between checking if the
                API has completed. If None then the default value, configured as
                CloudAssetClient.OPERATION_DELAY_IN_SEC, is used.

        Returns:
            dict: Operation status and info.

        Raises:
            OperationTimeoutError: Raised if the operation times out.
        """
        if operation.get('done', False):
            return operation

        if initial_delay is None:
            initial_delay = self.OPERATION_DELAY_IN_SEC

        if retry_delay is None:
            retry_delay = self.OPERATION_DELAY_IN_SEC

        started_timestamp = time.time()
        time.sleep(initial_delay)

        while True:
            operation_name = operation['name']
            operation = self.get_operation(operation_name)
            if operation.get('done', False):
                return operation

            if timeout and time.time() - started_timestamp > timeout:
                raise api_errors.OperationTimeoutError(parent, operation)

            time.sleep(retry_delay)
