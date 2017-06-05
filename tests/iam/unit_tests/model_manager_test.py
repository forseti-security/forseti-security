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

""" Unit Tests: Database abstraction objects for IAM Explain. """

from tests.unittest_utils import ForsetiTestCase
import uuid
import os

from google.cloud.security.iam.dao import ModelManager, session_creator, create_engine
from google.cloud.security.common.util.threadpool import ThreadPool

def create_test_engine():
    tmpfile = '/tmp/{}.db'.format(uuid.uuid4())
    return create_engine('sqlite:///{}'.format(tmpfile)), tmpfile

class ModelManagerTest(ForsetiTestCase):
    """Test for dao.ModelManager create/delete/list."""

    def setUp(self):
        self.engine, self.dbfile = create_test_engine()
        self.model_manager = ModelManager(self.engine)

    def tearDown(self):
        os.unlink(self.dbfile)

    def test_create_get_delete_one_model(self):
        """Start with no models, create one, delete it again."""
        self.assertEquals(0, len(self.model_manager.models()),
                          'Expecting no models to exist')
        handle = self.model_manager.create()
        self.assertEqual([handle], self.model_manager.models(),
                         'Expecting the created model to be listed')
        self.model_manager.delete(handle)
        self.assertEqual(0, len(self.model_manager.models()),
                         'Expecting no models to exist after deletion')

    def test_create_get_delete_multiple_models(self):
        """Start with no models, create multiple, delete them again."""
        self.assertEqual(0, len(self.model_manager.models()),
                         'Expecting no models to exist')
        handles = []
        num_handles = 32
        for _ in range(num_handles):
            handles.append(self.model_manager.create())

        self.assertEqual(set(handles), set(self.model_manager.models()),
                         'Expecting the created models to be listed')

        self.assertEqual(len(handles), num_handles)

        for i in range(num_handles):
            self.model_manager.delete(handles[i])
        self.assertEqual(0, len(self.model_manager.models()),
                         'Expecting no models to exist after deletion')

    def test_concurrent_access(self):
        """
        Start with no models, create multiple, delete them again, concurrent.
        """
        return
        num_threads = 16
        thread_pool = ThreadPool(num_threads)

        def test_func():
            """Create, get, delete models."""
            for _ in range(32):
                model = self.model_manager.create()
                self.assertTrue(model in self.model_manager.models())
                self.model_manager.delete(model)
                self.assertTrue(model not in self.model_manager.models())
            return True
        for _ in range(num_threads):
            thread_pool.add_func(test_func)
        thread_pool.join()
        self.assertTrue(len(self.model_manager.models()) == 0,
                        'Expecting no models to stick around')
