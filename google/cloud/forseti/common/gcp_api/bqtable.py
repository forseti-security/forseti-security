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

"""Wrapper for the Bqtable API client."""
from httplib2 import HttpLib2Error
from googleapiclient import errors

from google.cloud.forseti.common.gcp_api import _base_repository
from google.cloud.forseti.common.gcp_api import api_helpers
from google.cloud.forseti.common.gcp_api import errors as api_errors
from google.cloud.forseti.common.gcp_api import repository_mixins
from google.cloud.forseti.common.util import logger

LOGGER = logger.get_logger(__name__)

important_log = ''

class _BqtableRepository(
        repository_mixins.GetQueryMixin,  #If you need get API
        repository_mixins.ListQueryMixin, #If you need list API
       _base_repository.GCPRepository):
   """Implementation of Tables on Bigquery repository."""

   def __init__(self, **kwargs):
       """Constructor.

       Args:
           **kwargs (dict): The args to pass into GCPRepository.__init__()
       """
       global important_log
       important_log = str(type(kwargs))+';;'+str(type(kwargs['gcp_service']))
       super(_BqtableRepository, self).__init__(
           key_field=None, component='tables', **kwargs)


class BqtableRepositoryClient(_base_repository.BaseRepositoryClient):
    """Bqtable API Respository."""

    def __init__(self,
                quota_max_calls=None,
                quota_period=100.0,
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

        self._tables = None

        super(BqtableRepositoryClient, self).__init__(
            'bigquery', versions=['v2'],
            quota_max_calls=quota_max_calls,
            quota_period=quota_period,
            use_rate_limiter=use_rate_limiter)

    # Turn off docstrings for properties.
    # pylint: disable=missing-return-doc, missing-return-type-doc
    @property
    def tables(self):
        """Returns a _BqtableRepository instance."""
        if not self._tables:
            self._tables = self._init_repository(_BqtableRepository)
        return self._tables
    # pylint: enable=missing-return-doc, missing-return-type-doc


class BqtableClient(object):
    """Bqtable Client manager."""

    def __init__(self, global_configs, **kwargs):
        """Initialize.

        Args:
            global_configs (dict): Forseti config.
            **kwargs (dict): The kwargs.
        """
        max_calls, quota_period = api_helpers.get_ratelimiter_config(
            global_configs, 'bigquery')

        self.repository = BqtableRepositoryClient(
            quota_max_calls=max_calls,
            quota_period=quota_period,
            use_rate_limiter=kwargs.get('use_rate_limiter', True))

    def get_tables(self, project_id, dataset_id):
        """Request and page through bqtable.

        Returns:
            list: A list of sth for bqtable. E.g. A list of data of buckets

            If there are no result for bqtable an empty list will
            be returned.
        """
        try:
            results = self.repository.tables.list(
                projectId=project_id, datasetId=dataset_id)
            flattened_results = api_helpers.flatten_list_results(
                results, 'tables')
            LOGGER.info('get tables %s from project %s', important_log, project_id)
        except (errors.HttpError, HttpLib2Error) as e:
            raise api_errors.ApiExecutionError('bqtable', e)

        return flattened_results
