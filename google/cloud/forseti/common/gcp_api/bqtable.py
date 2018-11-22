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
           'bqtable', versions=['v2'],
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
