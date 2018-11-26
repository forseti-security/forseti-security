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

"""Tests the GCP Resource 'key' functionality class."""

import mock
import unittest

from tests.unittest_utils import ForsetiTestCase
from google.cloud.forseti.common.gcp_type import backend_service
from google.cloud.forseti.common.gcp_type import instance_group
from google.cloud.forseti.common.gcp_type import instance
from google.cloud.forseti.common.gcp_type import instance_template
from google.cloud.forseti.common.gcp_type import key
from google.cloud.forseti.common.gcp_type import project
from google.cloud.forseti.common.gcp_type import network


class KeyTest(ForsetiTestCase):
    """Test resource keys."""

    def test_generic(self):
        """Test generic Key functionality."""
        url_1 = ('https://www.googleapis.com/compute/v1/'
                 'projects/foo/global/things/bar')
        url_2 = ('https://www.googleapis.com/compute/v1/'
                 'projects/flub/global/things/bar')
        url_3 = ('https://www.googleapis.com/compute/v1/'
                 'projects/foo/global/things/blah')
        url_4 = ('https://www.googleapis.com/compute/v1/'
                 'projects/foo/scopes/kwyjibo/things/bar')
        key_1 = key.Key('Thing', {'project_id': 'foo',
                                  'scope': None,
                                  'name': 'bar'})
        key_2 = key.Key('Thing', {'project_id': 'flub',
                                  'scope': None,
                                  'name': 'bar'})
        key_3 = key.Key('Thing', {'project_id': 'foo',
                                  'scope': None,
                                  'name': 'blah'})
        key_4 = key.Key('Thing', {'project_id': 'foo',
                                  'scope': 'kwyjibo',
                                  'name': 'bar'})
        path_component_map = {'projects': 'project_id',
                              'things': 'name',
                              'scopes': 'scope'}
        from_url = lambda url: key.Key._from_url('Thing',
                                                 path_component_map,
                                                 url)
        self.assertEqual(key_1, from_url(url_1))
        self.assertEqual(key_2, from_url(url_2))
        self.assertEqual(key_3, from_url(url_3))
        self.assertEqual(key_4, from_url(url_4))
        self.assertNotEqual(key_1, key_2)
        self.assertNotEqual(key_1, key_3)
        self.assertNotEqual(key_1, key_4)

        url_invalid_1 = ('https://www.googleapis.com/compute/v1/'
                         'xxx/yyy')
        url_invalid_2 = ('https://www.googleapis.com/compute/v1/'
                         'projects/foo/things')
        self.assertRaises(ValueError, from_url, url_invalid_1)
        self.assertRaises(ValueError, from_url, url_invalid_2)

    def test_backend_service(self):
        """Test backend_service.Key."""
        url_1 = ('https://www.googleapis.com/compute/v1/'
                 'projects/foo/global/backendServices/bar')
        url_2 = ('https://www.googleapis.com/compute/v1/'
                 'projects/foo/regions/bar/backendServices/baz')
        obj_1 = backend_service.BackendService(
            project_id='foo',
            name='bar')
        obj_2 = backend_service.BackendService(
            project_id='foo',
            region='bar',
            name='baz')
        key_1 = key.Key(backend_service.KEY_OBJECT_KIND,
                        {'project_id': 'foo',
                         'name': 'bar',
                         'region': None})
        key_2 = key.Key(backend_service.KEY_OBJECT_KIND,
                        {'project_id': 'foo',
                         'name': 'baz',
                         'region': 'bar'})
        self.assertEqual(key_1, obj_1.key)
        self.assertEqual(key_1,
                         backend_service.Key.from_url(url_1))
        self.assertEqual(key_2, obj_2.key)
        self.assertEqual(key_2,
                         backend_service.Key.from_url(url_2))

        url_invalid_1 = ('https://www.googleapis.com/compute/v1/'
                         'projects/foo')
        url_invalid_2 = ('https://www.googleapis.com/compute/v1/'
                         'backendServices/foo')
        self.assertRaises(ValueError, backend_service.Key.from_url,
                          url_invalid_1)
        self.assertRaises(ValueError, backend_service.Key.from_url,
                          url_invalid_2)

    def test_instance_group(self):
        """Test instance_group.Key."""
        url_1 = ('https://www.googleapis.com/compute/v1/'
                 'projects/foo/regions/us-central1/instanceGroups/bar')
        url_2 = ('https://www.googleapis.com/compute/v1/'
                 'projects/foo/zones/us-central1-a/instanceGroups/bar')
        obj_1 = instance_group.InstanceGroup(
            project_id='foo',
            region='us-central1',
            name='bar')
        obj_2 = instance_group.InstanceGroup(
            project_id='foo',
            zone='us-central1-a',
            name='bar')
        key_1 = key.Key(instance_group.KEY_OBJECT_KIND,
                        {'project_id': 'foo',
                         'region': 'us-central1',
                         'zone': None,
                         'name': 'bar'})
        key_2 = key.Key(instance_group.KEY_OBJECT_KIND,
                        {'project_id': 'foo',
                         'region': None,
                         'zone': 'us-central1-a',
                         'name': 'bar'})
        self.assertEqual(key_1, obj_1.key)
        self.assertEqual(key_1,
                         instance_group.Key.from_url(url_1))
        self.assertEqual(key_2, obj_2.key)
        self.assertEqual(key_2,
                         instance_group.Key.from_url(url_2))

        url_invalid_1 = ('https://www.googleapis.com/compute/v1/'
                         'projects/foo/zones/bar')
        url_invalid_2 = ('https://www.googleapis.com/compute/v1/'
                         'zones/bar/instanceGroups/baz')
        url_invalid_3 = ('https://www.googleapis.com/compute/v1/'
                         'projects/foo/instanceGroups/bar')
        url_invalid_4 = ('https://www.googleapis.com/compute/v1/'
                         'projects/foo/zones/a/regions/b/instanceGroups/bar')
        self.assertRaises(ValueError, instance_group.Key.from_url,
                          url_invalid_1)
        self.assertRaises(ValueError, instance_group.Key.from_url,
                          url_invalid_2)
        self.assertRaises(ValueError, instance_group.Key.from_url,
                          url_invalid_3)
        self.assertRaises(ValueError, instance_group.Key.from_url,
                          url_invalid_4)

    def test_instance(self):
        """Test instance.Key."""
        url_1 = ('https://www.googleapis.com/compute/v1/'
                 'projects/foo/zones/us-central1-a/instances/bar')
        obj_1 = instance.Instance(
            'bar',
            parent=project.Project('foo'),
            locations=['us-central1-a'],
            name='bar')
        key_1 = key.Key(instance.KEY_OBJECT_KIND,
                        {'project_id': 'foo',
                         'zone': 'us-central1-a',
                         'name': 'bar'})
        self.assertEqual(key_1, obj_1.key)
        self.assertEqual(key_1,
                         instance.Key.from_url(url_1))

        url_invalid_1 = ('https://www.googleapis.com/compute/v1/'
                         'zones/bar/instances/baz')
        url_invalid_2 = ('https://www.googleapis.com/compute/v1/'
                         'projects/foo/instances/bar')
        url_invalid_3 = ('https://www.googleapis.com/compute/v1/'
                         'projects/foo/zones/bar')
        self.assertRaises(ValueError, instance.Key.from_url,
                          url_invalid_1)
        self.assertRaises(ValueError, instance.Key.from_url,
                          url_invalid_2)
        self.assertRaises(ValueError, instance.Key.from_url,
                          url_invalid_3)

    def test_instance_template(self):
        """Test instance_template.Key."""
        url_1 = ('https://www.googleapis.com/compute/v1/'
                 'projects/foo/global/instanceTemplates/bar')
        obj_1 = instance_template.InstanceTemplate(
            project_id='foo',
            name='bar')
        key_1 = key.Key(instance_template.KEY_OBJECT_KIND,
                        {'project_id': 'foo',
                         'name': 'bar'})
        self.assertEqual(key_1, obj_1.key)
        self.assertEqual(key_1,
                         instance_template.Key.from_url(url_1))

        url_invalid_1 = ('https://www.googleapis.com/compute/v1/'
                         'projects/foo')
        url_invalid_2 = ('https://www.googleapis.com/compute/v1/'
                         'instanceTemplates/bar')
        self.assertRaises(ValueError, instance_template.Key.from_url,
                          url_invalid_1)
        self.assertRaises(ValueError, instance_template.Key.from_url,
                          url_invalid_2)

    def test_network(self):
        """Test network.Key."""
        url_1 = ('https://www.googleapis.com/compute/v1/'
                 'projects/foo/global/networks/bar')
        url_1a = 'global/networks/bar'
        url_2 = 'projects/blah/global/networks/bar'
        key_1 = key.Key(network.KEY_OBJECT_KIND,
                        {'project_id': 'foo',
                         'name': 'bar'})
        key_2 = key.Key(network.KEY_OBJECT_KIND,
                        {'project_id': 'blah',
                         'name': 'bar'})
        self.assertEqual(key_1,
                         network.Key.from_url(url_1))
        self.assertEqual(key_1,
                         network.Key.from_url(url_1, project_id='blah'))
        self.assertEqual(key_1,
                         network.Key.from_url(url_1a, project_id='foo'))
        self.assertEqual(key_2,
                         network.Key.from_url(url_2, project_id='foo'))

        url_invalid_1 = ('https://www.googleapis.com/compute/v1/'
                         'projects/foo')
        url_invalid_2 = ('https://www.googleapis.com/compute/v1/'
                         'networks/bar')
        self.assertRaises(ValueError, network.Key.from_url,
                          url_invalid_1)
        self.assertRaises(ValueError, network.Key.from_url,
                          url_invalid_2)


if __name__ == '__main__':
    unittest.main()
