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

"""Provides the data access object (DAO) for buckets."""

from google.cloud.security.common.data_access import project_dao
from google.cloud.security.common.util import log_util

LOGGER = log_util.get_logger(__name__)


class CloudsqlDao(project_dao.ProjectDao):
    """Data access object (DAO) for Organizations."""

    def __init__(self):
        super(CloudsqlDao, self).__init__()
