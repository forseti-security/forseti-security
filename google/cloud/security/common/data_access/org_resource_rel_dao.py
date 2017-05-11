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

"""DAO for organization resource entity relationships."""

from google.cloud.security.common.data_access import dao
from google.cloud.security.common.gcp_type import resource


class OrgResourceRelDao(dao.Dao):
    """DAO for organization resource entity relationships."""

    # TODO: create a map for the resource type => dao

    def find_ancestors(self, resource):
        """Find ancestors of a particular resource.

        Args:
            resource: A Resource.

        Returns:
            A list of ancestors, starting with the closest ancestor.
        """

