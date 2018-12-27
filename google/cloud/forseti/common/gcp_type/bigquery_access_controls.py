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


# pylint: disable=too-many-instance-attributes,too-many-arguments
class BigqueryAccessControls(object):
    """BigQuery ACL Resource."""

    def __init__(self, project_id, dataset_id, full_name,
                 special_group, user_email, domain, group_email, role,
                 view, raw_json):
        """Initialize.

        Args:
            project_id (str): the project id
            dataset_id (str): BigQuery dataset_id
            full_name (str): The full resource name and ancestory.
            special_group (str): BigQuery access_special_group
            user_email (str): BigQuery access_by_user_email
            domain (str): BigQuery access_domain
            group_email (str): BigQuery access_group_by_email
            role (str): GCP role
            view (dict): The BigQuery view the acl applies to.
            raw_json (str): The raw json string for the acl.

        """
        self.project_id = project_id
        self.dataset_id = dataset_id
        self.full_name = full_name
        self.special_group = special_group
        self.user_email = user_email
        self.domain = domain
        self.group_email = group_email
        self.role = role
        self.view = view
        self.json = raw_json

    @classmethod
    def from_dict(cls, project_id, dataset_id, full_name, acl):
        """Returns a new BigqueryAccessControls object from dict.

        Args:
            project_id (str): the project id
            dataset_id (str): BigQuery dataset_id
            full_name (str): The full resource name and ancestory.
            acl (dict): The Bigquery Dataset Access ACL.

        Returns:
            BigqueryAccessControls: A new BigqueryAccessControls object.
        """
        return cls(
            project_id=project_id,
            dataset_id=dataset_id,
            full_name=full_name,
            domain=acl.get('domain'),
            user_email=acl.get('userByEmail'),
            special_group=acl.get('specialGroup'),
            group_email=acl.get('groupByEmail'),
            role=acl.get('role', ''),
            view=acl.get('view', {}),
            raw_json=json.dumps(acl, sort_keys=True)
        )

    @staticmethod
    def from_json(project_id, dataset_id, full_name, acls):
        """Yields a new BigqueryAccessControls object from for each acl.

        Args:
            project_id (str): the project id
            dataset_id (str): BigQuery dataset_id
            full_name (str): The full resource name and ancestory.
            acls (str): The json dataset access list.

        Yields:
            BigqueryAccessControls: A new BigqueryAccessControls object for
                each acl in acls.
        """
        acls = json.loads(acls)
        for acl in acls:
            yield BigqueryAccessControls.from_dict(
                project_id, dataset_id, full_name, acl)

    def __hash__(self):
        """Return hash of properties.

        Returns:
            hash: The hash of the class properties.
        """
        return hash(self.json)
