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

"""A Compute Network.

See: https://cloud.google.com/compute/docs/reference/beta/networks
"""


from google.cloud.security.common.gcp_type import key


KEY_OBJECT_KIND = 'Network'


class Key(key.Key):

    @staticmethod
    def from_args(project_id, name):
        return Key(KEY_OBJECT_KIND, {
            'project_id': project_id,
            'name': name})

    @staticmethod
    def from_url(url, project_id=None):
        """Accepts relative network 'URLs' as seen in firewall rule resources.

           xref:
           https://cloud.google.com/compute/docs/reference/latest/firewalls
        """
        if '://' not in url:
            url = 'https://www.googleapis.com/compute/v1/%s' % url
        obj = Key._from_url(KEY_OBJECT_KIND,
                            {'projects': 'project_id',
                             'networks': 'name'},
                            url)
        if obj.name is None or (project_id is None and
                                    obj.project_id is None):
            raise ValueError('Missing fields in URL %r' % url)
        elif obj.project_id is None:
            obj._set_path_component('project_id', project_id)
        return obj

    @property
    def project_id(self):
        return self._path_component('project_id')

    @property
    def name(self):
        return self._path_component('name')
