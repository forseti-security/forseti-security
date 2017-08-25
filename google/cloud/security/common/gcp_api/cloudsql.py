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

from googleapiclient import errors
from httplib2 import HttpLib2Error

from google.cloud.security.common.gcp_api import _base_repository
from google.cloud.security.common.gcp_api import errors as api_errors
from google.cloud.security.common.util import log_util

LOGGER = log_util.get_logger(__name__)


class CloudSqlRepository(_base_repository.BaseRepositoryClient):
    """Cloud SQL Admin API Respository."""

    def __init__(self,
                 quota_max_calls=None,
                 quota_period=1.0,
                 use_rate_limiter=True):
        """Constructor.

        Args:
          quota_max_calls (int): Allowed requests per <quota_period> for the
              API.
          quota_period (float): The time period to limit the quota_requests to.
          use_rate_limiter (bool): Set to false to disable the use of a rate
              limiter for this service.
        """
        if not quota_max_calls:
            use_rate_limiter = False

        self._instances = None

        super(CloudSqlRepository, self).__init__(
            'sqladmin', versions=['v1beta4'],
            quota_max_calls=quota_max_calls,
            quota_period=quota_period,
            use_rate_limiter=use_rate_limiter)

    # Turn off docstrings for properties.
    # pylint: disable=missing-return-doc, missing-return-type-doc
    @property
    def instances(self):
        """Returns a _CloudSqlInstancesRepository instance."""
        if not self._instances:
            self._instances = self._init_repository(
                _CloudSqlInstancesRepository)

        return self._instances
    # pylint: enable=missing-return-doc, missing-return-type-doc

class _CloudSqlInstancesRepository(
        _base_repository.ListQueryMixin,
        _base_repository.GCPRepository):
    """Implementation of CloudSql Instances repository."""

    def __init__(self, **kwargs):
        """Constructor.

        Args:
          **kwargs (dict): The args to pass into GCPRepository.__init__()
        """
        super(_CloudSqlInstancesRepository, self).__init__(
            component='instances', **kwargs)


class CloudsqlClient(object):
    """CloudSQL Client."""

    DEFAULT_QUOTA_TIMESPAN_PER_SECONDS = 100.0  # pylint: disable=invalid-name

    def __init__(self, global_configs, **kwargs):
        """Initialize.

        Args:
            global_configs (dict): Global configurations.
            **kwargs (dict): The kwargs.
        """
        max_calls = global_configs.get('max_sqladmin_api_calls_per_100_seconds')
        self.repository = CloudSqlRepository(
            quota_max_calls=max_calls,
            quota_period=self.DEFAULT_QUOTA_TIMESPAN_PER_SECONDS,
            use_rate_limiter=kwargs.get('use_rate_limiter', True))

    def get_instances(self, project_id):
        """Gets all CloudSQL instances for a project.

        Args:
            project_id (int): The project id for a GCP project.

        Returns:
            list: A list of database Instance resource dicts for a project_id.
            https://cloud.google.com/sql/docs/mysql/admin-api/v1beta4/instances

            [{"kind": "sql#instance", "name": "sql_instance1", ...}
             {"kind": "sql#instance", "name": "sql_instance2", ...},
             {...}]

        Raises:
            ApiExecutionError: ApiExecutionError is raised if the call to the
                GCP ClodSQL API fails
        """

        try:
            paged_results = self.repository.instances.list(project_id)
            return _base_repository.flatten_list_results(paged_results,
                                                         'items')
        except (errors.HttpError, HttpLib2Error) as e:
            LOGGER.warn(api_errors.ApiExecutionError(project_id, e))
            raise api_errors.ApiExecutionError('instances', e)
