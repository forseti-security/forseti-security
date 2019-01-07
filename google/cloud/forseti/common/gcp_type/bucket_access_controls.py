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
"""A Bucket ACL Resource."""

import json


# pylint: disable=too-many-instance-attributes
class BucketAccessControls(object):
    """Bucket ACL Resource.
    """
    def __init__(self, project_id, bucket, full_name, entity, email, domain,
                 role, raw_json):
        """Initialize

        Args:
            project_id (str): The project id.
            bucket (str): GCS bucket name.
            full_name (str): The full resource name and ancestory.
            entity (str): GCS entity.
            email (str): email.
            domain (str): domain.
            role (str): GCS role.
            raw_json (str): The raw json string for the acl.
        """
        self.project_id = project_id
        self.bucket = bucket
        self.full_name = full_name
        self.entity = entity
        self.email = email
        self.domain = domain
        self.role = role
        self.json = raw_json

    @classmethod
    def from_dict(cls, project_id, full_name, acl):
        """Returns a new BucketAccessControls object from dict.

        Args:
            project_id (str): The project id.
            full_name (str): The full resource name and ancestory.
            acl (dict): The Bucket ACL.

        Returns:
            BucketAccessControls: A new BucketAccessControls object.
        """
        return cls(
            project_id=project_id,
            bucket=acl.get('bucket', ''),
            full_name=full_name,
            entity=acl.get('entity', ''),
            email=acl.get('email', ''),
            domain=acl.get('domain', ''),
            role=acl.get('role', ''),
            raw_json=json.dumps(acl, sort_keys=True)
        )

    @staticmethod
    def from_json(project_id, full_name, acls):
        """Yields a new BucketAccessControls object from for each acl.

        Args:
            project_id (str): the project id.
            full_name (str): The full resource name and ancestory.
            acls (str): The json bucket acl list.

        Yields:
            BucketAccessControls: A new BucketAccessControls object for
                each acl in acls.
        """
        acls = json.loads(acls)
        for acl in acls:
            yield BucketAccessControls.from_dict(
                project_id, full_name, acl)

    @staticmethod
    def from_list(project_id, full_name, acls):
        """Yields a new BucketAccessControls object from for each acl.

        Args:
            project_id (str): the project id.
            full_name (str): The full resource name and ancestory.
            acls (list): The bucket acl list.

        Yields:
            BucketAccessControls: A new BucketAccessControls object for
                each acl in acls.
        """
        for acl in acls:
            yield BucketAccessControls.from_dict(
                project_id, full_name, acl)

    def __hash__(self):
        """Return hash of properties.

        Returns:
            hash: The hash of the class properties.
        """
        return hash(self.json)
