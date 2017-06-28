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

""" Unit Tests: Importer for IAM Explain. """

import os

from tests.unittest_utils import ForsetiTestCase
from google.cloud.security.iam.dao import create_engine
from google.cloud.security.iam.dao import ModelManager
from google.cloud.security.iam.explain.importer import importer


class ServiceConfig(object):
    """
    ServiceConfig is a helper class to implement dependency injection
    to IAM Explain services.
    """

    def __init__(self, explain_connect_string, forseti_connect_string):
        engine = create_engine(explain_connect_string, echo=False)
        self.model_manager = ModelManager(engine)
        self.forseti_connect_string = forseti_connect_string

    def run_in_background(self, function):
        """Runs a function in a thread pool in the background."""
        return function()


def get_db_file_path(db_name):
    module_dir = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(module_dir, 'test_data', db_name)


class ImporterTest(ForsetiTestCase):
    """Test importer based on database dump."""

    def test_status_done(self):
        """Test if the status of the import is 'done'."""

        EXPLAIN_CONNECT = 'sqlite:///:memory:'
        FORSETI_CONNECT = 'sqlite:///{}'.format(
            get_db_file_path('forseti_1_basic.db'))

        self.service_config = ServiceConfig(EXPLAIN_CONNECT,
                                            FORSETI_CONNECT)
        self.source = 'FORSETI'
        self.model_manager = self.service_config.model_manager
        self.model_name = self.model_manager.create(name=self.source)

        scoped_session, data_access = self.model_manager.get(self.model_name)
        with scoped_session as session:

            importer_cls = importer.by_source(self.source)
            import_runner = importer_cls(
                session,
                self.model_manager.model(self.model_name, expunge=False),
                data_access,
                self.service_config)
            import_runner.run()

        model = self.model_manager.model(self.model_name)
        self.assertEqual(model.state,
                         'SUCCESS',
                         'Model state should be set to SUCCESS')

    def test_missing_group_collection(self):
        """Test if a missing group membership table is handled"""
        EXPLAIN_CONNECT = 'sqlite:///:memory:'
        FORSETI_CONNECT = 'sqlite:///{}'.format(
            get_db_file_path('forseti_1_missing_groups.db'))

        self.service_config = ServiceConfig(EXPLAIN_CONNECT,
                                            FORSETI_CONNECT)
        self.source = 'FORSETI'
        self.model_manager = self.service_config.model_manager
        self.model_name = self.model_manager.create(name=self.source)

        scoped_session, data_access = self.model_manager.get(self.model_name)
        with scoped_session as session:

            importer_cls = importer.by_source(self.source)
            import_runner = importer_cls(
                session,
                self.model_manager.model(self.model_name, expunge=False),
                data_access,
                self.service_config)
            import_runner.run()

        model = self.model_manager.model(self.model_name)
        self.assertEqual(model.state, 'BROKEN', 'Model state should be BROKEN')

        error_msg = 'Did you enable Forseti group collection?'
        self.assertTrue(error_msg in model.message)
