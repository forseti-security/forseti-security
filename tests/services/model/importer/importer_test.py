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

import os
import shutil
import tempfile
import unittest
from tests.unittest_utils import ForsetiTestCase
from google.cloud.forseti.common.util import date_time
from google.cloud.forseti.common.util import string_formats
from google.cloud.forseti.services.dao import create_engine
from google.cloud.forseti.services.dao import ModelManager
from google.cloud.forseti.services.model.importer import importer

FAKE_TIMESTAMP = date_time.get_utc_now_datetime().strftime(
    string_formats.TIMESTAMP_MICROS)


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
    """Test importer based on database dump.

        Note: If the GCP data and/or schema changes see:
            tests/services/model/importer/update_test_dbs.py
    """

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

            importer_cls = importer.by_source(self.source)
            import_runner = importer_cls(
                session,
                self.model_manager.model(self.model_name,
                                         expunge=False,
                                         session=session),
                data_access,
                self.service_config,
                inventory_id=FAKE_TIMESTAMP)
            import_runner.run()

            # make sure the 'full_name' for policies has an even number of
            # segments
            for policy in data_access.scanner_iter(session, 'iam_policy'):
                self.assertFalse(
                        len(filter(None, policy.full_name.split('/'))) % 2)

        model = self.model_manager.model(self.model_name)
        model_description = self.model_manager.get_description(self.model_name)

        self.assertIn(model.state,
                      ['SUCCESS', 'PARTIAL_SUCCESS'],
                      'Model state should be success or partial success: %s' %
                      model.message)
        self.assertEquals(
            {'pristine': True,
             'source': 'inventory',
             'source_info': {'inventory_index_id': FAKE_TIMESTAMP},
             'source_root': 'organization/111222333',
             'gsuite_enabled': True
             },
            model_description)

if __name__ == '__main__':
    unittest.main()
