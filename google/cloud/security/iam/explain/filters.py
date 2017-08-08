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

""" filter classes """

from datetime import datetime
# pylint: disable=missing-type-doc, missing-param-doc
# pylint: disable=missing-return-type-doc, missing-return-doc
# pylint: disable=singleton-comparison

class TimeFilter(object):
    """Time Filter class."""
    def __init__(self, explaine_filter=None):
        """To generate a python filter from protobuf filter"""
        if not explaine_filter:
            self.has_start_from = False
            self.has_end_at = False
            self.start_from = datetime(1970, 1, 1, 0, 0, 0)
            self.end_at = datetime(1970, 1, 1, 0, 0, 0)
            self.list_untimed_resources = False
        else:
            self.has_start_from = explaine_filter.has_start_from
            self.has_end_at = explaine_filter.has_end_at
            self.start_from = explaine_filter.start_from.ToDatetime()
            self.end_at = explaine_filter.end_at.ToDatetime()
            self.list_untimed_resources = explaine_filter.list_untimed_resources

    def __call__(self, cls, qry):
        """To apply Time Filter on a query"""
        to_filter = self.has_start_from | self.has_end_at
        if to_filter:
            resource = cls.TBL_RESOURCE
            res_qry = qry.join(resource)
            if self.has_start_from:
                res_qry = res_qry.filter(resource.create_time
                                         >= self.start_from)
            if self.has_end_at:
                res_qry = res_qry.filter(resource.create_time <= self.end_at)
            if self.list_untimed_resources:
                res_qry = res_qry.union(qry.join(resource)
                                        .filter(resource.create_time == None))
            return res_qry
        else:
            return qry

    def is_satisfied(self, resource):
        """To apply Time Filter on a single resource"""
        to_filter = self.has_start_from | self.has_end_at
        if to_filter:
            if not resource.create_time:
                return self.list_untimed_resources
            return (((not self.has_start_from)
                     | (resource.create_time >= self.start_from))
                    &((not self.has_end_at)
                      | (resource.create_time <= self.end_at)))
        else:
            return True
