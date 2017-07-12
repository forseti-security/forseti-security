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

"""A Compute Backend Service.

See: https://cloud.google.com/compute/docs/reference/latest/backendServices
"""


from google.cloud.security.common.gcp_type import key


# pylint: disable=too-many-instance-attributes
class BackendService(object):
    """Represents BackendService resource."""

    def __init__(self, **kwargs):
        """BackendService resource.

        Args:
            kwargs: The object's attributes.
        """
        self.affinity_cookie_ttl_sec = kwargs.get('affinity_cookie_ttl_sec')
        self.backends = kwargs.get('backends')
        self.cdn_policy = kwargs.get('cdn_policy')
        self.connection_draining = kwargs.get('connection_draining')
        self.creation_timestamp = kwargs.get('creation_timestamp')
        self.description = kwargs.get('description')
        self.enable_cdn = kwargs.get('enable_cdn')
        self.health_checks = kwargs.get('health_checks')
        self.iap = kwargs.get('iap')
        self.load_balancing_scheme = kwargs.get('load_balancing_scheme')
        self.name = kwargs.get('name')
        self.port = kwargs.get('port')
        self.port_name = kwargs.get('port_name')
        self.project_id = kwargs.get('project_id')
        self.protocol = kwargs.get('protocol')
        self.region = kwargs.get('region')
        self.resource_id = kwargs.get('id')
        self.session_affinity = kwargs.get('session_affinity')
        self.timeout_sec = kwargs.get('timeout_sec')

    @property
    def key(self):
        """Returns a Key identifying the object.

        Returns:
            Key: the key
        """
        return Key.from_args(self.project_id, self.name, region=self.region)


KEY_OBJECT_KIND = 'BackendService'


class Key(key.Key):
    """An identifier for a specific backend service."""

    # Backend services can be regional or global.
    @staticmethod
    def from_args(project_id, name, region=None):
        """Construct a Key from specific values.

        Args:
            project_id (str): project_id
            name (str): name
            region (str): region (optional)

        Returns:
            Key: the key
        """
        return Key(KEY_OBJECT_KIND, {
            'project_id': project_id,
            'name': name,
            'region': region})

    @staticmethod
    def from_url(url):
        """Construct a Key from a URL.

        Args:
            url (str): Object reference URL

        Returns:
            Key: the key

        Raises:
            ValueError: Required parameters are missing.
        """
        obj = Key._from_url(
            KEY_OBJECT_KIND,
            {'projects': 'project_id',
             'regions': 'region',
             'backendServices': 'name'},
            url)
        if obj.project_id is None or obj.name is None:
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
