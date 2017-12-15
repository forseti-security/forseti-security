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

"""BigQuery ACL Resource."""

import json


# pylint: disable=too-few-public-methods
class BigqueryAccessControls(object):
    """BigQuery ACL Resource."""

    def __init__(self, project_id, dataset_id, special_group, user_email,
                 domain, group_email, role, view, json):
        """Initialize.

        Args:
            project_id (str): the project id
            dataset_id (str): BigQuery dataset_id
            special_group (str): BigQuery access_special_group
            user_email (str): BigQuery access_by_user_email
            domain (str): BigQuery access_domain
            group_email (str): BigQuery access_group_by_email
            role (str): GCP role
            view (dict): The BigQuery view the acl applies to.
            json (str): The raw json string for the acl.

        """
        self.project_id = project_id
        self.dataset_id = dataset_id
        self.special_group = special_group
        self.user_email = user_email
        self.domain = domain
        self.group_email = group_email
        self.role = role
        self.view = view
        self.json = json

    @classmethod
    def from_dict(cls, project_id, dataset_id, acl):
        """Returns a new BigqueryAccessControls object from dict."""
        return cls(
            project_id=project_id,
            dataset_id=dataset_id,
            domain=acl.get('domain', ''),
            user_email=acl.get('userByEmail', ''),
            special_group=acl.get('specialGroup', ''),
            group_email=acl.get('groupByEmail', ''),
            role=acl.get('role', ''),
            view=acl.get('view', {}),
            json=json.dumps(acl)
        )

    @staticmethod
    def from_json(project_id, dataset_id, acls):
        """Yields a new BigqueryAccessControls object from for each acl."""
        acls = json.loads(acls)
        for acl in acls:
            yield BigqueryAccessControls.from_dict(
                project_id, dataset_id, acl)

    def __hash__(self):
        """Return hash of properties.

        Returns:
            hash: The hash of the class properties.
        """
        return hash(self.json)
