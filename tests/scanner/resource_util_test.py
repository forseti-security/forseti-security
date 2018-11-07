from datetime import datetime
import json
# pylint says unittest goes before mock
import unittest
import mock

# pylint says sqlalchemy.orm goes before google.auth

import google.auth
from google.oauth2 import credentials

from google.cloud.forseti.common.gcp_api import cloud_resource_manager as crm
from google.cloud.forseti.common.gcp_api import api_helpers
from google.cloud.forseti.common.gcp_type import resource_util
from tests.common.gcp_api.test_data import fake_crm_responses
from tests.unittest_utils import ForsetiTestCase

class ResourceUtilTest(ForsetiTestCase):
    """Test misc."""

    def setUp(self):
        """Set up."""
        fake_global_configs = {
            'crm': {'max_calls': 4, 'period': 1.2}}

        mock.patch.object(google.auth, 'default', return_value=(
            mock.Mock(spec_set=credentials.Credentials), 'test-project'))

        mock_creds = api_helpers.get_delegated_credential('user1@eaxmple.com', mock.MagicMock())

        self.crm_api_client = crm.CloudResourceManagerClient(
            global_configs=fake_global_configs,
            use_rate_limiter=False,
            credentials=mock_creds)
        self.project_id = fake_crm_responses.FAKE_PROJECT_ID

    def test_cast_to_gcp_resources(self):
        """Validate get_project_ancestry_resources() with test project."""
        expected_cast_resources = "[project<id=forseti-system-test,parent=None>, folder<id=3333333,parent=None>, organization<id=2222222,parent=None>]"
        api_result = [{u'resourceId': {u'type': u'project', u'id': u'forseti-system-test'}}, {u'resourceId': {u'type': u'folder', u'id': u'3333333'}}, {u'resourceId': {u'type': u'organization', u'id': u'2222222'}}]

        cast_resources = resource_util.cast_to_gcp_resources(api_result)
        self.assertEqual(expected_cast_resources, str(cast_resources))
