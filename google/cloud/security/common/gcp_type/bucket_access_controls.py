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
"""A Bucket ACL Resource."""


# pylint: disable=too-few-public-methods
class BucketAccessControls(object):
    """Bucket ACL Resource.
    """
    def __init__(self, bucket, entity, email, domain, role,
                 project_number=None):
        """Initialize

        Args:
            bucket (str): GCS bucket
            entity (str): GCS entity
            email (str): email
            domain (str): domain
            role (str): GCS role
            project_number (int): the project number
        """
        self.bucket = bucket
        self.entity = entity
        self.email = email
        self.domain = domain
        self.role = role
        self.project_number = project_number

    def __hash__(self):
        """Return hash of properties.

        Returns:
            hash: returns the hash of the class properties.
        """
        return hash((self.bucket, self.entity, self.email, self.domain,
                     self.role, self.project_number))
