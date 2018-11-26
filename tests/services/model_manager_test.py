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
"""Unit Tests: Database abstraction objects for Forseti Server."""

import os
import unittest
from tests.unittest_utils import ForsetiTestCase
from tests.services.util.db import create_test_engine_with_file
from google.cloud.forseti.common.util.threadpool import ThreadPool
from google.cloud.forseti.services.dao import ModelManager


class ModelManagerTest(ForsetiTestCase):
    """Test for dao.ModelManager create/delete/list."""

    def setUp(self):
        self.engine, self.dbfile = create_test_engine_with_file()
        self.model_manager = ModelManager(self.engine)

    def tearDown(self):
        os.unlink(self.dbfile)

    def test_create_get_delete_one_model(self):
        """Start with no models, create one, delete it again."""
        self.assertEquals(0, len(self.model_manager.models()),
                          'Expecting no models to exist')
        handle = self.model_manager.create(name='test_model')
        self.assertEqual([handle],
                         [m.handle for m in self.model_manager.models()],
                         'Expecting the created model to be listed')
        self.model_manager.delete(handle)
        self.assertEqual(0, len(self.model_manager.models()),
                         'Expecting no models to exist after deletion')

    def test_create_get_delete_multiple_models(self):
        """Start with no models, create multiple, delete them again."""
        self.assertEqual(0, len(self.model_manager.models()),
                         'Expecting no models to exist')
        handles = []
        num_models = 32
        for i in range(num_models):
            handles.append(self.model_manager.create(name=str(i)))

        self.assertEqual(set(handles),
                         set([m.handle for m in self.model_manager.models()]),
                         'Expecting the created models to be listed')

        self.assertEqual(len(handles), num_models)

        for i in range(num_models):
            self.model_manager.delete(handles[i])
        self.assertEqual(0, len(self.model_manager.models()),
                         'Expecting no models to exist after deletion')

    @unittest.skip("Concurrent access leads to memory corruption.")
    def test_concurrent_access(self):
        """Start with no models, create multiple, delete them again, concurrent.
        """
        num_threads = 4
        thread_pool = ThreadPool(num_threads)

        def test_func(x):
            """Create, get, delete models."""
            for i in range(32):
                handle = self.model_manager.create(name='%s-%s' % (x, i))
                self.assertTrue(
                    handle in [m.handle for m in self.model_manager.models()])
                self.model_manager.delete(handle)
                self.assertTrue(
                    handle not in
                        [m.handle for m in self.model_manager.models()])
            return True
        for x in range(num_threads):
            thread_pool.add_func(test_func, x)
        thread_pool.join()
        self.assertTrue(len(self.model_manager.models()) == 0,
                        'Expecting no models to stick around')


if __name__ == '__main__':
    unittest.main()
