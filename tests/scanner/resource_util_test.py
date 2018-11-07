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

    def test_cast_to_gcp_resources(self):
        """Validate get_project_ancestry_resources() with test project."""
        expected_cast_resources = "[project<id=forseti-system-test,parent=None>, folder<id=3333333,parent=None>, organization<id=2222222,parent=None>]"
        api_result = [{u'resourceId': {u'type': u'project', u'id': u'forseti-system-test'}}, {u'resourceId': {u'type': u'folder', u'id': u'3333333'}}, {u'resourceId': {u'type': u'organization', u'id': u'2222222'}}]

        cast_resources = resource_util.cast_to_gcp_resources(api_result)
        self.assertEqual(expected_cast_resources, str(cast_resources))
