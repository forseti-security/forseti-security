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
"""Unit Tests: Importer for Forseti Server."""

import mock
import os
import shutil
import tempfile
import unittest

from datetime import datetime

from tests.unittest_utils import ForsetiTestCase
from google.cloud.forseti.common.util import date_time
from google.cloud.forseti.services.dao import create_engine
from google.cloud.forseti.services.dao import ModelManager
from google.cloud.forseti.services.model.importer import importer
from google.cloud.forseti.services.model.importer.importer import InventoryImporter

FAKE_DATETIME = datetime(2018, 1, 28, 10, 20, 30, 0)
FAKE_DATETIME_TIMESTAMP = date_time.get_utc_now_microtimestamp(FAKE_DATETIME)


class ServiceConfig(object):
    """Helper class to implement dependency injection to Forseti Server services.
    """

    def __init__(self, db_connect_string):
        engine = create_engine(db_connect_string, echo=False)
        self.model_manager = ModelManager(engine)

    def run_in_background(self, function):
        """Runs a function in a thread pool in the background."""
        return function()


def get_db_file_path(db_name):
    module_dir = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(module_dir, 'test_data', db_name)


def get_db_file_copy(filename):
    """Return a temp copy of the test db."""
    fd, dstfilename = tempfile.mkstemp()
    shutil.copyfile(get_db_file_path(filename), dstfilename)
    try:
        return dstfilename
    finally:
        os.close(fd)


class ImporterTest(ForsetiTestCase):
    """Test importer based on database dump."""

    def test_inventory_importer_basic(self):
        """Test the basic importer for the inventory."""

        db_connect = 'sqlite:///{}'.format(
            get_db_file_copy('forseti-test.db'))

        print db_connect

        self.service_config = ServiceConfig(db_connect)

        self.source = 'INVENTORY'
        self.model_manager = self.service_config.model_manager
        self.model_name = self.model_manager.create(name=self.source)

        scoped_session, data_access = self.model_manager.get(self.model_name)

        with scoped_session as session:
            # Sqlite really doesn't like multiple connections, and sqlalchemy
            # is effectively a connection per session, reusing the same session
            # for read and write.
            importer_cls = importer.by_source(self.source)
            import_runner = importer_cls(
                session,
                session,
                self.model_manager.model(self.model_name,
                                         expunge=False,
                                         session=session),
                data_access,
                self.service_config,
                inventory_index_id=FAKE_DATETIME_TIMESTAMP)
            import_runner.run()

            # Make sure the 'full_name' for policies has an even number of
            # segments.
            for policy in data_access.scanner_iter(session, 'iam_policy'):
                self.assertFalse(
                        len(filter(None, policy.full_name.split('/'))) % 2)

        # Make sure binding_members table is populated properly when there are users with multiple
        # roles in different projects.
        expected_abc_user_accesses = [
            ('roles/appengine.codeViewer', ['project/project3']),
            ('roles/appengine.appViewer', ['project/project3'])
        ]
        abc_user_accesses = data_access.query_access_by_member(session, 'user/abc_user@forseti.test', [])
        self.assertEqual(expected_abc_user_accesses, abc_user_accesses)

        model = self.model_manager.model(self.model_name)
        model_description = self.model_manager.get_description(self.model_name)

        self.assertIn(model.state,
                      ['SUCCESS', 'PARTIAL_SUCCESS'],
                      'Model state should be success or partial success: %s' %
                      model.message)
        self.assertEquals(
            {'pristine': True,
             'source': 'inventory',
             'source_info': {'inventory_index_id': FAKE_DATETIME_TIMESTAMP},
             'source_root': 'organization/111222333',
             'gsuite_enabled': True
             },
            model_description)

    def test_model_action_wrapper_post_action_called(self):
        session = mock.Mock()
        session.flush = mock.Mock()
        inventory_iter = []
        action = mock.Mock()
        post = mock.Mock()
        flush_count = 1
        InventoryImporter.model_action_wrapper(session,
                                               inventory_iter,
                                               action,
                                               post,
                                               flush_count)
        post.assert_called_once()

    def test_model_action_wrapper_inventory_iter_tuple(self):
        """If inventory iter is of type tuple, it will call the
        action with the data as positional args."""
        session = mock.Mock()
        session.flush = mock.Mock()
        inventory_iter = [(1, 2)]
        action = mock.Mock()
        post = mock.Mock()
        flush_count = 1
        count = InventoryImporter.model_action_wrapper(session,
                                                       inventory_iter,
                                                       action,
                                                       post,
                                                       flush_count)

        action.assert_called_once_with(1, 2)
        self.assertEquals(1, count)

        # post is always called if exists
        self.assertTrue(post.called)

        # flush count is 1, flush should be called once since there is 1 item
        session.flush.assert_called()
        self.assertEqual(session.flush.call_count, 1)

    def test_model_action_wrapper_multiple_inventory_iter_tuples(self):
        session = mock.Mock()
        session.flush = mock.Mock()
        inventory_iter = [(1, 2), (4, 5)]
        action = mock.Mock()
        post = mock.Mock()
        flush_count = 1
        count = InventoryImporter.model_action_wrapper(session,
                                                       inventory_iter,
                                                       action,
                                                       post,
                                                       flush_count)

        calls = [mock.call(1, 2), mock.call(4, 5)]
        action.assert_has_calls(calls)
        self.assertEquals(2, count)

        # post is always called if exists
        self.assertTrue(post.called)

        # flush count is 1, flush should be called twice since there are 2 items
        session.flush.assert_called()
        self.assertEqual(session.flush.call_count, 2)

    def test_model_action_wrapper_inventory_iter_value(self):
        """If inventory iter is not tuple, it will call the
        action with the data as positional args."""
        session = mock.Mock()
        session.flush = mock.Mock()
        inventory_iter = ['not_tuple']
        action = mock.Mock()
        post = mock.Mock()
        flush_count = 1
        count = InventoryImporter.model_action_wrapper(session,
                                                       inventory_iter,
                                                       action,
                                                       post,
                                                       flush_count)

        action.assert_called_once_with('not_tuple')
        self.assertEquals(1, count)

        # post is always called if exists
        self.assertTrue(post.called)

        # flush count is 1, flush should be called once since there is 1 item
        session.flush.assert_called()
        self.assertEqual(session.flush.call_count, 1)

    def test_model_action_wrapper_multiple_inventory_iter_values(self):
        session = mock.Mock()
        session.flush = mock.Mock()
        inventory_iter = ['data', 'data1']
        action = mock.Mock()
        post = mock.Mock()
        flush_count = 1
        count = InventoryImporter.model_action_wrapper(session,
                                                       inventory_iter,
                                                       action,
                                                       post,
                                                       flush_count)

        calls = [mock.call('data'), mock.call('data1')]
        action.assert_has_calls(calls)
        self.assertEquals(2, count)

        # post is always called if exists
        self.assertTrue(post.called)

        # flush count is 1, flush should be called twice since there are 2 items
        session.flush.assert_called()
        self.assertEqual(session.flush.call_count, 2)

if __name__ == '__main__':
    unittest.main()
