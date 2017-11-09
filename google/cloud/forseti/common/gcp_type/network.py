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

"""A Compute Network.

See: https://cloud.google.com/compute/docs/reference/beta/networks
"""


from google.cloud.forseti.common.gcp_type import key


KEY_OBJECT_KIND = 'Network'


class Key(key.Key):
    """An identifier for a specific network."""

    @staticmethod
    def from_args(project_id, name):
        """Construct a Key from specific values.

        Args:
            project_id (str): project_id
            name (str): name

        Returns:
            Key: the key
        """
        return Key(KEY_OBJECT_KIND, {
            'project_id': project_id,
            'name': name})

    @staticmethod
    def from_url(url, project_id=None):
        """Construct a Key from a URL.

           Accepts relative network 'URLs' as seen in firewall rule resources.
           xref:
           https://cloud.google.com/compute/docs/reference/latest/firewalls

        Args:
            url (str): Object reference URL
            project_id (str): Default project ID if, in the case of a relative
                              URL, none is present

        Returns:
            Key: the key

        Raises:
            ValueError: Required parameters are missing.
        """
        if '://' not in url:
            url = 'https://www.googleapis.com/compute/v1/%s' % url
        obj = Key._from_url(KEY_OBJECT_KIND,
                            {'projects': 'project_id',
                             'networks': 'name'},
                            url,
                            defaults={'project_id': project_id})
        if not obj.name or not obj.project_id:
            raise ValueError('Missing fields in URL %r' % url)
        return obj

    @property
    def project_id(self):
        """Object property: project_id

        Returns:
            str: project_id
        """
        return self._path_component('project_id')

    @property
    def name(self):
        """Object property: name

        Returns:
            str: name
        """
        return self._path_component('name')
