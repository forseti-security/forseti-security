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


class BucketLifeCycleItem(object):
    def __init__(self, actiontype, age):
        self.actiontype = actiontype
        self.age = age

    def __str__(self):
        return "act:"+str(self.actiontype)+";age:"+str(self.age)

# pylint: disable=too-many-instance-attributes
class RetentionBucket(object):
    """Bucket ACL Resource.
    """
    def __init__(self, name, tp, full_name, lifecycleitems, raw_json):
        """Initialize

        Args:
            raw_json (str): The raw json string for the acl.
        """
        self.name = name
        self.type = tp
        self.full_name = full_name
        self.lifecycleitems = lifecycleitems
        self.json = raw_json

    @classmethod
    def from_dict(cls, bucketdata, name, tp, full_name_):
        """Returns a new BucketAccessControls object from dict.

        Args:
            project_id (str): The project id.
            full_name (str): The full resource name and ancestory.
            acl (dict): The Bucket ACL.

        Returns:
            BucketAccessControls: A new BucketAccessControls object.
        """
        lifecycleitems = []
        if(bucketdata.has_key('lifecycle') and bucketdata.get('lifecycle').has_key('rule')):
            lifecycleitems = bucketdata['lifecycle']['rule']
        return cls(
            name = name,
            tp = tp,
            full_name = full_name_,
            lifecycleitems = lifecycleitems,
            raw_json = json.dumps(bucketdata)
        )

    @staticmethod
    def from_json(bucketdata):
        """Yields a new BucketAccessControls object from for each acl.

        Args:
            project_id (str): the project id.
            full_name (str): The full resource name and ancestory.
            acls (str): The json bucket acl list.

        Yields:
            BucketAccessControls: A new BucketAccessControls object for
                each acl in acls.
        """
        bucketdatadict = json.loads(bucketdata.data)
        #bucketdata = json.loads(bucketdata)
        return RetentionBucket.from_dict(bucketdatadict, bucketdata.name, bucketdata.type, bucketdata.full_name)

    def __hash__(self):
        """Return hash of properties.

        Returns:
            hash: The hash of the class properties.
        """
        return hash(self.json)

    def __str__(self):
        strret = str(self.name)
        for lifecycleitem in self.lifecycleitems:
            strret = strret + " --" + str(lifecycleitem)
        return strret
