# Copyright 2019 The Forseti Security Authors. All rights reserved.
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

"""Tests the Config Validator data model pipeline builder."""

import unittest.mock as mock

from tests.unittest_utils import ForsetiTestCase
from google.cloud.forseti.scanner.scanners.config_validator_util.data_models import data_model_builder
from tests.scanner.test_data import fake_data_models


FAKE_GLOBAL_CONFIGS = {
    'db_host': 'foo',
    'db_user': 'bar',
    'db_name': 'baz'
}


class DataModelBuilderTest(ForsetiTestCase):
    """Tests for the Config Validator data model builder."""

    def test_all_enabled(self):
        builder = (
            data_model_builder
                .DataModelBuilder(FAKE_GLOBAL_CONFIGS,
                                  fake_data_models.ALL_ENABLED,
                                  mock.MagicMock(),
                                  ''))
        data_model_pipeline = builder.build()
        self.assertEqual(1, len(data_model_pipeline))
        expected_data_models = ['CaiDataModel']
        for data_model in data_model_pipeline:
            self.assertTrue(type(data_model).__name__ in expected_data_models)

    def test_all_disabled(self):
        builder = (
            data_model_builder
                .DataModelBuilder(FAKE_GLOBAL_CONFIGS,
                                  fake_data_models.ALL_DISABLED,
                                  mock.MagicMock(),
                                  ''))
        data_model_pipeline = builder.build()
        self.assertEqual(0, len(data_model_pipeline))

    def test_non_existent_data_model_is_handled(self):
        builder = data_model_builder.DataModelBuilder(
            FAKE_GLOBAL_CONFIGS,
            fake_data_models.NONEXISTENT_DATA_MODEL_ENABLED,
            mock.MagicMock(),
            '')
        data_models = builder.build()
        self.assertEqual(1, len(data_models))
