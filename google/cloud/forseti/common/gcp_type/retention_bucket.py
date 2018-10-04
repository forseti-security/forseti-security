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
"""A Bucket ACL Resource."""

import json


# pylint: disable=too-many-instance-attributes
class RetentionBucket(object):
    """Bucket Retention Resource.
    """
    def __init__(self, name, full_name, lifecycleitems, raw_json):
        """Bucket Retention resource.
        Args:
          name (str):            The name of the bucket.
          full_name (str):       The full name of the bucket
          lifecycleitems (list): A list of dicts that contains actions ("delete") and conditions ("age")
          raw_json (str):        The data of the bucket
        """

        self.name = name
        self.type = 'bucket'
        self.full_name = full_name
        self.lifecycleitems = lifecycleitems
        self.json = raw_json

    @classmethod
    def from_dict(cls, bucketdata, name, full_name):
        """Returns a new BucketAccessControls object from dict.

        Args:
            bucketdata (dict): The bucket data.
            name (str): The bucket name.
            full_name (str): The full bucket name and ancestory.

        Returns:
            RetentionBucket: A new RetentionBucket object.
        """
        lifecycleitems = []
        if(bucketdata.has_key('lifecycle') and bucketdata.get('lifecycle').has_key('rule')):
            lifecycleitems = bucketdata['lifecycle']['rule']
        return cls(
            name = name,
            full_name = full_name,
            lifecycleitems = lifecycleitems,
            raw_json = json.dumps(bucketdata)
        )

    @staticmethod
    def from_json(bucketdata):
        """Return a new RetentionBucket object from for bucket data.

        Args:
            bucketdata (Resource): The bucket resource.

        Returns:
            RetentionBucket: A new RetentionBucket object
        """
        bucketdatadict = json.loads(bucketdata.data)
        return RetentionBucket.from_dict(bucketdatadict, bucketdata.name, bucketdata.full_name)

    def __hash__(self):
        """Return hash of properties.

        Returns:
            hash: The hash of the class properties.
        """
        return hash(self.json)
        