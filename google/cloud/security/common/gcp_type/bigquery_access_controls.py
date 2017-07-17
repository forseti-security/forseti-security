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

"""BigQuery ACL Resource."""


# pylint: disable=too-few-public-methods
class BigqueryAccessControls(object):
    """BigQuery ACL Resource."""

    def __init__(self, dataset_id, special_group, user_email, domain,
                 group_email, role, project_id=None):
        """Initialize.

        Args:
            dataset_id (str): BigQuery dataset_id
            special_group (str): BigQuery access_special_group
            user_email (str): BigQuery access_by_user_email
            domain (str): BigQuery access_domain
            group_email (str): BigQuery access_group_by_email
            role (str): GCP role
            project_id (str): the project id
        """
        self.dataset_id = dataset_id
        self.special_group = special_group
        self.user_email = user_email
        self.domain = domain
        self.group_email = group_email
        self.role = role
        self.project_id = project_id

    def __hash__(self):
        """Return hash of properties.

        Returns:
            hash: The hash of the class properties.
        """
        return hash((self.dataset_id, self.special_group, self.user_email,
                     self.domain, self.group_email, self.role,
                     self.project_id))
