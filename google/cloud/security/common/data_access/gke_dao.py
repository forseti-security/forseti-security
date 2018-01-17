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

"""Provides the data access object (DAO) for GKE."""

from google.cloud.security.common.data_access import dao
from google.cloud.security.common.util import log_util


LOGGER = log_util.get_logger(__name__)


class GkeDao(dao.Dao):
    """"Data access object (DAO) for AppEngine."""

    pass
