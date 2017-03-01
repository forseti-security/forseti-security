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

import json
import os

from google.apputils import basetest
from google.cloud.security.inventory import transform_util
from tests.inventory.test_data.fake_iam_policies import EXPECTED_FLATTENED_ORG_IAM_POLICY
from tests.inventory.test_data.fake_iam_policies import EXPECTED_FLATTENED_PROJECT_IAM_POLICY
from tests.inventory.test_data.fake_iam_policies import FAKE_ORG_IAM_POLICY_MAP
from tests.inventory.test_data.fake_iam_policies import FAKE_PROJECT_IAM_POLICY_MAP


class TransformUtilTest(basetest.TestCase):

    def test_can_flatten_projects(self):
        current_dir_path = os.path.dirname(os.path.abspath(__file__))
        projects_json_path = os.path.join(
            current_dir_path, 'test_data', 'projects.json')
        with open(projects_json_path, 'r') as f:
            projects = json.loads(f.read())

        expected_projects_json_path = os.path.join(
            current_dir_path, 'test_data', 'expected_flattened_projects.json')
        with open(expected_projects_json_path, 'r') as f:
            expected_projects = json.loads(f.read())

        projects = transform_util.flatten_projects(projects)
        for (i, project) in enumerate(projects):
            # Normalize to python representation.
            project['raw_project'] = json.loads(project['raw_project'])
            project = json.loads(json.dumps(project))
            self.assertEquals(expected_projects[i], project)

    def test_can_parse_member_info(self):
        member = 'serviceAccount:55555555-compute@developer.gserviceaccount.com'
        member_type, member_name, member_domain = (
            transform_util._parse_member_info(member))
        self.assertEquals('serviceAccount', member_type)
        self.assertEquals('55555555-compute', member_name)
        self.assertEquals('developer.gserviceaccount.com', member_domain)

        member = 'domain:foo.com'
        member_type, member_name, member_domain = (
            transform_util._parse_member_info(member))
        self.assertEquals('domain', member_type)
        self.assertEquals('', member_name)
        self.assertEquals('foo.com', member_domain)

    def test_can_flatten_org_iam_policies(self):
        flattened_iam_policies = transform_util.flatten_iam_policies(FAKE_ORG_IAM_POLICY_MAP)
        self.assertEquals(EXPECTED_FLATTENED_ORG_IAM_POLICY, list(flattened_iam_policies))

    def test_can_flatten_project_iam_policies(self):
        flattened_iam_policies = transform_util.flatten_iam_policies(FAKE_PROJECT_IAM_POLICY_MAP)
        self.assertEquals(EXPECTED_FLATTENED_PROJECT_IAM_POLICY, list(flattened_iam_policies))


if __name__ == '__main__':
    basetest.main()
