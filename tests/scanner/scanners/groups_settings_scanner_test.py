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

"""Groups Settings Scanner Tests."""

from builtins import object
import unittest
import mock
import json
from datetime import datetime

from tests import unittest_utils
from tests.services.util.db import create_test_engine
from tests.scanner.test_data.fake_groups_settings_scanner_data import (
    SETTINGS_1, SETTINGS_3, SETTINGS_5, SETTINGS)
from google.cloud.forseti.common.gcp_type import resource as resource_mod
from google.cloud.forseti.scanner.scanners import groups_settings_scanner
from google.cloud.forseti.common.util.string_formats import TIMESTAMP_MICROS
from google.cloud.forseti.services.dao import ModelManager


"""
Rule 1 mainly tests that blacklist picks up violations when
and only when all specified properties are matched

Rule 2 mainly tests that scanner works with specific resource ids
(other rules use wild cards)

Rule 3 mainly tests that whitelist breaks when and only
when at least one specified property is violated
"""

class FakeServiceConfig(object):

    def __init__(self):
        engine = create_test_engine()
        self.model_manager = ModelManager(engine)


class GroupsSettingsScannerTest(unittest_utils.ForsetiTestCase):

    @classmethod
    def setUpClass(cls):
        cls.service_config = FakeServiceConfig()
        cls.model_name = cls.service_config.model_manager.create(
            name='groups-settings-scanner-test')

        scoped_session, data_access = (
            cls.service_config.model_manager.get(cls.model_name))

        def add_settings_to_test_db(settings_row):
            data_access.add_member(session, settings_row['group_name'])
            stmt = data_access.TBL_GROUPS_SETTINGS.insert(settings_row)
            session.execute(stmt)
            session.commit()

        # Add organization to model.
        with scoped_session as session:
           for settings_row in SETTINGS:
                add_settings_to_test_db(settings_row)

    def setUp(self):
        self.scanner = groups_settings_scanner.GroupsSettingsScanner(
            {}, {}, self.service_config, self.model_name,
            '', unittest_utils.get_datafile_path(
                __file__, 'groups_settings_scanner_test_rules.yaml'))

    @mock.patch.object(
        groups_settings_scanner.GroupsSettingsScanner,
        '_output_results_to_db', autospec=True)
    def test_run_scanner(self, mock_output_results):
        self.scanner.run()
        all_groups_settings, iam_groups_settings = self.scanner._retrieve()
        violations = self.scanner._find_violations(all_groups_settings, 
                                                   iam_groups_settings)
        self.assertEquals(1, mock_output_results.call_count)
        self.assertEquals(3, len(violations))
        self.assertEquals(json.loads(SETTINGS_1['settings'])['email'], 
                          violations[0].group_email)
        self.assertEquals(json.loads(SETTINGS_3['settings'])['email'], 
                          violations[1].group_email)
        self.assertEquals(json.loads(SETTINGS_5['settings'])['email'], 
                          violations[2].group_email)


if __name__ == '__main__':
    unittest.main()
