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
"""Scanner runner script test."""

from datetime import datetime
import mock
import unittest

from google.cloud.forseti.common.util import string_formats
from google.cloud.forseti.common.gcp_type.billing_account import BillingAccount
from google.cloud.forseti.common.gcp_type.bucket import Bucket
from google.cloud.forseti.common.gcp_type.dataset import Dataset
from google.cloud.forseti.common.gcp_type.folder import Folder
from google.cloud.forseti.common.gcp_type import iam_policy
from google.cloud.forseti.common.gcp_type.organization import Organization
from google.cloud.forseti.common.gcp_type.project import Project
from google.cloud.forseti.scanner.scanners import iam_rules_scanner
from tests.unittest_utils import ForsetiTestCase


class IamRulesScannerTest(ForsetiTestCase):

    @mock.patch(
        'google.cloud.forseti.scanner.scanners.iam_rules_scanner.iam_rules_engine',
        autospec=True)
    def setUp(self, mock_rules_engine):

        self.fake_utcnow = datetime(
            year=1900, month=1, day=1, hour=0, minute=0, second=0,
            microsecond=0)

        self.scanner = iam_rules_scanner.IamPolicyScanner(
            {}, {}, mock.MagicMock(), '', '', '')
        self._add_ancestor_bindings_test_data()

    def _add_ancestor_bindings_test_data(self):
        """Establishes the hierarchy below.

               +-----------> billing_acct_abcd
               |
               |
               +----------------------------> proj_1 +-------> dataset_1_1
               |
               |
               +                                     +-------> bucket_3_1
            org_234 +------> folder_1 +-----> proj_3 |
                                                     +-------> bucket_3_2
               +
               |
               +----------------------------> proj_2 +-------> bucket_2_1
        """
        self.org_234 = Organization(
            '234',
            display_name='Organization 234',
            full_name='organization/234/',
            data='fake_org_data_234')

        self.billing_acct_abcd = BillingAccount(
            'ABCD-1234',
            display_name='Billing Account ABCD',
            parent=self.org_234,
            full_name='organization/234/billing_account/ABCD-1234/',
            data='fake_billing_account_data_abcd')

        self.proj_1 = Project(
            'proj-1',
            project_number=22345,
            display_name='My project 1',
            parent=self.org_234,
            full_name='organization/234/project/proj-1/',
            data='fake_project_data_111')

        self.dataset_1_1 = Dataset(
            'proj-1:dataset-1-1',
            display_name='Dataset 1.1',
            parent=self.proj_1,
            full_name='organization/234/project/proj-1/dataset/proj-1:dataset-1-1',
            data='dataset_data')

        self.proj_2 = Project(
            'proj-2',
            project_number=22346,
            display_name='My project 2',
            parent=self.org_234,
            full_name='organization/234/project/proj-2/',
            data='fake_project_data_222')

        self.folder_1 = Folder(
            '333',
            display_name='Folder 1',
            parent=self.org_234,
            full_name='organization/234/folder/333/',
            data='fake_folder_data_111')

        self.proj_3 = Project(
            'proj-3',
            project_number=22347,
            display_name='My project 3',
            parent=self.folder_1,
            full_name='organization/234/folder/333/project/proj-3/',
            data='fake_project_data_333')

        self.bucket_3_1 = Bucket(
            'internal-3',
            display_name='My project 3, internal data1',
            parent=self.proj_3,
            full_name='organization/234/folder/333/project/proj-3/bucket/internal-3/',
            data='fake_project_data_333_bucket_1')

        self.bucket_3_2 = Bucket(
            'public-3',
            display_name='My project 3, public data',
            parent=self.proj_3,
            full_name='organization/234/folder/333/project/proj-3/bucket/public-3/',
            data='fake_project_data_333_bucket_2')

        self.bucket_2_1 = Bucket(
            'internal-2',
            display_name='My project 2, internal data',
            parent=self.proj_2,
            full_name='organization/234/project/proj-2/bucket/internal-2/',
            data='fake_project_data_222_bucket_1')

        self.org_234_policy_resource = mock.MagicMock()
        self.org_234_policy_resource.full_name = (
            'organization/234/iam_policy/organization:234/')

        self.billing_acct_abcd_policy_resource = mock.MagicMock()
        self.billing_acct_abcd_policy_resource.full_name = (
            'organization/234/billing_account/ABCD-1234/iam_policy'
            '/billing_account:ABCD-1234/')

        self.folder_1_policy_resource = mock.MagicMock()
        self.folder_1_policy_resource.full_name = (
            'organization/234/folder/333/iam_policy/folder:333/')

        self.proj_1_policy_resource = mock.MagicMock()
        self.proj_1_policy_resource.full_name = (
            'organization/234/project/proj-1/iam_policy/project:proj-1')

        self.proj_2_policy_resource = mock.MagicMock()
        self.proj_2_policy_resource.full_name = (
            'organization/234/project/proj-2/iam_policy/project:proj-2')

        self.proj_3_policy_resource = mock.MagicMock()
        self.proj_3_policy_resource.full_name = (
            'organization/234/folder/333/project/proj-3/iam_policy/project:proj-3')

        self.bucket_3_1_policy_resource = mock.MagicMock()
        self.bucket_3_1_policy_resource.full_name = (
            'organization/234/folder/333/project/proj-3/bucket/internal-3/iam_policy/bucket:internal-3')

        self.bucket_3_2_policy_resource = mock.MagicMock()
        self.bucket_3_2_policy_resource.full_name = (
            'organization/234/folder/333/project/proj-3/bucket/public-3/iam_policy/bucket:public-3')

        self.bucket_2_1_policy_resource = mock.MagicMock()
        self.bucket_2_1_policy_resource.full_name = (
            'organization/234/folder/333/project/proj-2/bucket/internal-2/iam_policy/bucket:internal-2')

        self.dataset_1_1_policy_resource = mock.MagicMock()
        self.dataset_1_1_policy_resource.full_name = (
            'organization/234/project/proj-1/dataset/proj-1:dataset-1-1/iam_policy/dataset:proj-1:dataset-1-1')


    def testget_output_filename(self):
        """Test that the output filename of the scanner is correct.

        Expected:
            * Scanner output filename matches the format.
        """
        fake_utcnow_str = self.fake_utcnow.strftime(
            string_formats.TIMESTAMP_TIMEZONE_FILES)

        expected = string_formats.SCANNER_OUTPUT_CSV_FMT.format(fake_utcnow_str)
        actual = self.scanner.get_output_filename(self.fake_utcnow)
        self.assertEquals(expected, actual)

    @mock.patch.object(
        iam_rules_scanner.IamPolicyScanner,
        '_output_results_to_db', autospec=True)
    @mock.patch.object(
        iam_rules_scanner.IamPolicyScanner,
        '_flatten_violations')
    # autospec on staticmethod will return noncallable mock
    def test_output_results(
            self, mock_flatten_violations, mock_output_results_to_db):
        """Test _output_results() flattens / stores results."""
        self.scanner._output_results(None)

        self.assertEqual(1, mock_flatten_violations.call_count)
        self.assertEqual(1, mock_output_results_to_db.call_count)

    def test_add_bucket_ancestor_bindings_nothing_found(self):
        """Test bucket with an org / project ancestry w/o relevant policies.

        Setup:
            * Use an org -> project -> bucket resource tree in which the
              project and org ancestors have no GCS relevant policies

        Expect:
            * the bucket's policy bindings do not change since there's nothing
              to pick up from the resource tree ancestors
        """
        org_policy = {
            'bindings': [
                {
                    'role': 'roles/owner',
                    'members': [
                        'user:owner@company.com',
                    ]
                }
            ]
        }
        org_bindings = filter(None, [ # pylint: disable=bad-builtin
            iam_policy.IamPolicyBinding.create_from(b)
            for b in org_policy.get('bindings')])
        policy_data = [
                (self.org_234, self.org_234_policy_resource, org_bindings)]
        proj_2_policy = {
            'bindings': [
                {
                    'role': 'roles/owner',
                    'members': [
                        'user:someone@company.com',
                    ]
                },
                {
                    'role': 'roles/viewer',
                    'members': [
                        'user:someone2@company.com',
                    ]
                },
            ]
        }
        proj_2_bindings = filter(None, [ # pylint: disable=bad-builtin
            iam_policy.IamPolicyBinding.create_from(b)
            for b in proj_2_policy.get('bindings')])
        policy_data.append(
                (self.proj_2, self.proj_2_policy_resource,
                    proj_2_bindings))

        bucket_bindings = []
        policy_data.append(
                (self.bucket_2_1, self.bucket_2_1_policy_resource,
                    bucket_bindings))

        iam_rules_scanner._add_bucket_ancestor_bindings(policy_data)
        self.assertEqual([], bucket_bindings)

    def test_add_bucket_ancestor_bindings_success(self):
        """Test bucket with an org / project ancestry with relevant policies.

        Setup:
            * Use an org -> project -> folder -> bucket resource tree in which
              both the project and the folder ancestors have GCS relevant
              policy bindings.
            * the project has a 'roles/storage.objectCreator' binding
            * the folder has a 'roles/storage.objectViewer' binding
            * the project has 2 buckets: bucket_3_1 and bucket_3_2 respectively

        Expect:
            * the folder's objectViewer and the project's objectCreator
              bindings will be added to both buckets' policy bindings.
        """
        org_policy = {
            'bindings': [
                {
                    'role': 'roles/owner',
                    'members': [
                        'user:owner@company.com',
                    ]
                }
            ]
        }
        org_bindings = filter(None, [ # pylint: disable=bad-builtin
            iam_policy.IamPolicyBinding.create_from(b)
            for b in org_policy.get('bindings')])
        policy_data = [
                (self.org_234, self.org_234_policy_resource, org_bindings)]
        folder_1_policy = {
            'bindings': [
                {
                    'role': 'roles/resourcemanager.folderEditor',
                    'members': [
                        'user:fe@company.com',
                    ]
                },
                {
                    'role': 'roles/storage.objectViewer',
                    'members': [
                        'user:someone@who.is.outsi.de',
                    ]
                },
            ]
        }
        folder_1_bindings = filter(None, [ # pylint: disable=bad-builtin
            iam_policy.IamPolicyBinding.create_from(b)
            for b in folder_1_policy.get('bindings')])
        policy_data.append(
                (self.folder_1, self.folder_1_policy_resource,
                    folder_1_bindings))
        proj_3_policy = {
            'bindings': [
                {
                    'role': 'roles/owner',
                    'members': [
                        'user:someone@company.com',
                    ]
                },
                {
                    'role': 'roles/storage.objectCreator',
                    'members': [
                        'user:someone@creative.com',
                    ]
                },
            ]
        }
        proj_3_bindings = filter(None, [ # pylint: disable=bad-builtin
            iam_policy.IamPolicyBinding.create_from(b)
            for b in proj_3_policy.get('bindings')])
        policy_data.append(
                (self.proj_3, self.proj_3_policy_resource,
                    proj_3_bindings))

        bucket_3_1_bindings = []
        policy_data.append(
                (self.bucket_3_1, self.bucket_3_1_policy_resource,
                    bucket_3_1_bindings))

        bucket_3_2_bindings = []
        policy_data.append(
                (self.bucket_3_2, self.bucket_3_2_policy_resource,
                    bucket_3_2_bindings))

        iam_rules_scanner._add_bucket_ancestor_bindings(policy_data)

        self.assertEqual(2, len(bucket_3_1_bindings))
        self.assertEqual(2, len(bucket_3_2_bindings))


        expected_policy = {
            'bindings': [
                {
                    'role': 'roles/storage.objectViewer',
                    'members': [
                        'user:someone@who.is.outsi.de',
                    ]
                },
                {
                    'role': 'roles/storage.objectCreator',
                    'members': [
                        'user:someone@creative.com',
                    ]
                },
            ]
        }
        expected_bindings = filter(None, [ # pylint: disable=bad-builtin
            iam_policy.IamPolicyBinding.create_from(b)
            for b in expected_policy.get('bindings')])

        self.assertEqual(expected_bindings, bucket_3_1_bindings)
        self.assertEqual(expected_bindings, bucket_3_2_bindings)

    def test_add_bucket_ancestor_bindings_same_role_different_members(self):
        """Test bucket with an org / project ancestry with relevant policies.

        Setup:
            * Use an org -> project -> folder -> bucket resource tree in which
              both the project and the folder ancestors have GCS relevant
              policy bindings.
            * both the folder and the project have a
              'roles/storage.objectCreator' binding but different members
            * the project has 2 buckets: bucket_3_1 and bucket_3_2 respectively
              but we just use the former for this test

        Expect:
            * the folder's and the project's objectCreator bindings will be
              added to the bucket's policy bindings with merged members.
        """
        org_policy = {
            'bindings': [
                {
                    'role': 'roles/owner',
                    'members': [
                        'user:owner@company.com',
                    ]
                }
            ]
        }
        org_bindings = filter(None, [ # pylint: disable=bad-builtin
            iam_policy.IamPolicyBinding.create_from(b)
            for b in org_policy.get('bindings')])
        policy_data = [
                (self.org_234, self.org_234_policy_resource, org_bindings)]
        folder_1_policy = {
            'bindings': [
                {
                    'role': 'roles/resourcemanager.folderEditor',
                    'members': [
                        'user:fe@company.com',
                    ]
                },
                {
                    'role': 'roles/storage.objectCreator',
                    'members': [
                        'user:someone@who.is.outsi.de',
                    ]
                },
            ]
        }
        folder_1_bindings = filter(None, [ # pylint: disable=bad-builtin
            iam_policy.IamPolicyBinding.create_from(b)
            for b in folder_1_policy.get('bindings')])
        policy_data.append(
                (self.folder_1, self.folder_1_policy_resource,
                    folder_1_bindings))
        proj_3_policy = {
            'bindings': [
                {
                    'role': 'roles/owner',
                    'members': [
                        'user:someone@company.com',
                    ]
                },
                {
                    'role': 'roles/storage.objectCreator',
                    'members': [
                        'user:someone@creative.com',
                    ]
                },
            ]
        }
        proj_3_bindings = filter(None, [ # pylint: disable=bad-builtin
            iam_policy.IamPolicyBinding.create_from(b)
            for b in proj_3_policy.get('bindings')])
        policy_data.append(
                (self.proj_3, self.proj_3_policy_resource,
                    proj_3_bindings))

        bucket_3_1_bindings = []
        policy_data.append(
                (self.bucket_3_1, self.bucket_3_1_policy_resource,
                    bucket_3_1_bindings))

        iam_rules_scanner._add_bucket_ancestor_bindings(policy_data)

        self.assertEqual(1, len(bucket_3_1_bindings))

        expected_policy = {
            'bindings': [
                {
                    'role': 'roles/storage.objectCreator',
                    'members': [
                        'user:someone@who.is.outsi.de',
                        'user:someone@creative.com',
                    ]
                },
            ]
        }
        expected_bindings = filter(None, [ # pylint: disable=bad-builtin
            iam_policy.IamPolicyBinding.create_from(b)
            for b in expected_policy.get('bindings')])

        self.assertEqual(expected_bindings, bucket_3_1_bindings)

    def test_add_bucket_ancestor_bindings_success_no_dups(self):
        """Test bucket with an org / project ancestry with relevant policies.

        Setup:
            * Use an org -> project -> folder -> bucket resource tree in which
              both the project and the folder ancestors have GCS relevant
              policy bindings.
            * the project has a 'roles/storage.objectViewer' binding
            * the folder also has a 'roles/storage.objectViewer' binding
            * the project has 2 buckets: bucket_3_1 and bucket_3_2 respectively
              but we use just the former for this test

        Expect:
            * the objectViewer binding will be added to the bucket's policy
              bindings (once).
        """
        org_policy = {
            'bindings': [
                {
                    'role': 'roles/owner',
                    'members': [
                        'user:owner@company.com',
                    ]
                }
            ]
        }
        org_bindings = filter(None, [ # pylint: disable=bad-builtin
            iam_policy.IamPolicyBinding.create_from(b)
            for b in org_policy.get('bindings')])
        policy_data = [
                (self.org_234, self.org_234_policy_resource, org_bindings)]
        folder_1_policy = {
            'bindings': [
                {
                    'role': 'roles/resourcemanager.folderEditor',
                    'members': [
                        'user:fe@company.com',
                    ]
                },
                {
                    'role': 'roles/storage.objectViewer',
                    'members': [
                        'user:someone@who.is.outsi.de',
                    ]
                },
            ]
        }
        folder_1_bindings = filter(None, [ # pylint: disable=bad-builtin
            iam_policy.IamPolicyBinding.create_from(b)
            for b in folder_1_policy.get('bindings')])
        policy_data.append(
                (self.folder_1, self.folder_1_policy_resource,
                    folder_1_bindings))
        proj_3_policy = {
            'bindings': [
                {
                    'role': 'roles/owner',
                    'members': [
                        'user:someone@company.com',
                    ]
                },
                {
                    'role': 'roles/storage.objectViewer',
                    'members': [
                        'user:someone@who.is.outsi.de',
                    ]
                },
            ]
        }
        proj_3_bindings = filter(None, [ # pylint: disable=bad-builtin
            iam_policy.IamPolicyBinding.create_from(b)
            for b in proj_3_policy.get('bindings')])
        policy_data.append(
                (self.proj_3, self.proj_3_policy_resource,
                    proj_3_bindings))

        bucket_3_1_bindings = []
        policy_data.append(
                (self.bucket_3_1, self.bucket_3_1_policy_resource,
                    bucket_3_1_bindings))

        iam_rules_scanner._add_bucket_ancestor_bindings(policy_data)

        self.assertEqual(1, len(bucket_3_1_bindings))


        expected_policy = {
            'bindings': [
                {
                    'role': 'roles/storage.objectViewer',
                    'members': [
                        'user:someone@who.is.outsi.de',
                    ]
                },
            ]
        }
        expected_bindings = filter(None, [ # pylint: disable=bad-builtin
            iam_policy.IamPolicyBinding.create_from(b)
            for b in expected_policy.get('bindings')])

        self.assertEqual(expected_bindings, bucket_3_1_bindings)

    def test_add_bucket_ancestor_bindings_with_wrong_ancestors(self):
        """Test bucket with an org / project ancestry w/o relevant policies.

        Setup:
            * Use an org -> project -> folder resource tree in which
              both the project and the folder ancestors have GCS relevant
              policy bindings.
            * the project has a 'roles/storage.objectCreator' binding
            * the folder has a 'roles/storage.objectViewer' binding
            * the bucket added is not a descendent of the project/folder in
              question though. It is attached to a different project ('proj_2')
              that has no GCS relevant policy bindings.

        Expect:
            * the folder's objectViewer and the project's objectCreator
              bindings will *not* be added to the bucket's policy bindings.
        """
        org_policy = {
            'bindings': [
                {
                    'role': 'roles/owner',
                    'members': [
                        'user:owner@company.com',
                    ]
                }
            ]
        }
        org_bindings = filter(None, [ # pylint: disable=bad-builtin
            iam_policy.IamPolicyBinding.create_from(b)
            for b in org_policy.get('bindings')])
        policy_data = [
                (self.org_234, self.org_234_policy_resource, org_bindings)]

        proj_2_policy = {
            'bindings': [
                {
                    'role': 'roles/owner',
                    'members': [
                        'user:someone@company.com',
                    ]
                },
                {
                    'role': 'roles/viewer',
                    'members': [
                        'user:someone2@company.com',
                    ]
                },
            ]
        }
        proj_2_bindings = filter(None, [ # pylint: disable=bad-builtin
            iam_policy.IamPolicyBinding.create_from(b)
            for b in proj_2_policy.get('bindings')])
        policy_data.append(
                (self.proj_2, self.proj_2_policy_resource,
                    proj_2_bindings))

        folder_1_policy = {
            'bindings': [
                {
                    'role': 'roles/resourcemanager.folderEditor',
                    'members': [
                        'user:fe@company.com',
                    ]
                },
                {
                    'role': 'roles/storage.objectViewer',
                    'members': [
                        'user:someone@who.is.outsi.de',
                    ]
                },
            ]
        }
        folder_1_bindings = filter(None, [ # pylint: disable=bad-builtin
            iam_policy.IamPolicyBinding.create_from(b)
            for b in folder_1_policy.get('bindings')])
        policy_data.append(
                (self.folder_1, self.folder_1_policy_resource,
                    folder_1_bindings))

        proj_3_policy = {
            'bindings': [
                {
                    'role': 'roles/owner',
                    'members': [
                        'user:someone@company.com',
                    ]
                },
                {
                    'role': 'roles/storage.objectCreator',
                    'members': [
                        'user:someone@creative.com',
                    ]
                },
            ]
        }
        proj_3_bindings = filter(None, [ # pylint: disable=bad-builtin
            iam_policy.IamPolicyBinding.create_from(b)
            for b in proj_3_policy.get('bindings')])
        policy_data.append(
                (self.proj_3, self.proj_3_policy_resource,
                    proj_3_bindings))

        bucket_bindings = []
        policy_data.append(
                (self.bucket_2_1, self.bucket_2_1_policy_resource,
                    bucket_bindings))

        iam_rules_scanner._add_bucket_ancestor_bindings(policy_data)
        self.assertEqual([], bucket_bindings)

    def test_add_bucket_ancestor_bindings_with_2_ancestor_lines(self):
        """Buckets with an independent org / project ancestry.

        Setup:
            * Use an org -> project -> folder resource tree in which
              both the project and the folder ancestors have GCS relevant
              policy bindings and 2 buckets.
            * Use another org -> project resource tree in which the project has
              GCS relevant policy bindings + a single bucket.

        Expect:
            * all 3 buckets will pick up the GCS relevant bindings.
        """
        org_policy = {
            'bindings': [
                {
                    'role': 'roles/owner',
                    'members': [
                        'user:owner@company.com',
                    ]
                }
            ]
        }
        org_bindings = filter(None, [ # pylint: disable=bad-builtin
            iam_policy.IamPolicyBinding.create_from(b)
            for b in org_policy.get('bindings')])
        policy_data = [
                (self.org_234, self.org_234_policy_resource, org_bindings)]

        proj_2_policy = {
            'bindings': [
                {
                    'role': 'roles/owner',
                    'members': [
                        'user:someone@company.com',
                    ]
                },
                {
                    'role': 'roles/storage.objectAdmin',
                    'members': [
                        'user:admin@storage.com',
                    ]
                },
            ]
        }
        proj_2_bindings = filter(None, [ # pylint: disable=bad-builtin
            iam_policy.IamPolicyBinding.create_from(b)
            for b in proj_2_policy.get('bindings')])
        policy_data.append(
                (self.proj_2, self.proj_2_policy_resource, proj_2_bindings))

        folder_1_policy = {
            'bindings': [
                {
                    'role': 'roles/resourcemanager.folderEditor',
                    'members': [
                        'user:fe@company.com',
                    ]
                },
                {
                    'role': 'roles/storage.objectViewer',
                    'members': [
                        'user:someone@who.is.outsi.de',
                    ]
                },
            ]
        }
        folder_1_bindings = filter(None, [ # pylint: disable=bad-builtin
            iam_policy.IamPolicyBinding.create_from(b)
            for b in folder_1_policy.get('bindings')])
        policy_data.append(
                (self.folder_1, self.folder_1_policy_resource,
                    folder_1_bindings))

        proj_3_policy = {
            'bindings': [
                {
                    'role': 'roles/owner',
                    'members': [
                        'user:someone@company.com',
                    ]
                },
                {
                    'role': 'roles/storage.objectCreator',
                    'members': [
                        'user:someone@creative.com',
                    ]
                },
            ]
        }
        proj_3_bindings = filter(None, [ # pylint: disable=bad-builtin
            iam_policy.IamPolicyBinding.create_from(b)
            for b in proj_3_policy.get('bindings')])
        policy_data.append(
                (self.proj_3, self.proj_3_policy_resource, proj_3_bindings))

        bucket_2_1_bindings = []
        policy_data.append(
                (self.bucket_2_1, self.bucket_2_1_policy_resource,
                    bucket_2_1_bindings))

        bucket_3_1_bindings = []
        policy_data.append(
                (self.bucket_3_1, self.bucket_3_1_policy_resource,
                    bucket_3_1_bindings))

        bucket_3_2_bindings = []
        policy_data.append(
                (self.bucket_3_2, self.bucket_3_2_policy_resource,
                    bucket_3_2_bindings))

        iam_rules_scanner._add_bucket_ancestor_bindings(policy_data)

        self.assertEqual(1, len(bucket_2_1_bindings))
        self.assertEqual(2, len(bucket_3_1_bindings))
        self.assertEqual(2, len(bucket_3_2_bindings))


        expected_b3_policy = {
            'bindings': [
                {
                    'role': 'roles/storage.objectViewer',
                    'members': [
                        'user:someone@who.is.outsi.de',
                    ]
                },
                {
                    'role': 'roles/storage.objectCreator',
                    'members': [
                        'user:someone@creative.com',
                    ]
                },
            ]
        }
        expected_b3_bindings = filter(None, [ # pylint: disable=bad-builtin
            iam_policy.IamPolicyBinding.create_from(b)
            for b in expected_b3_policy.get('bindings')])

        self.assertEqual(expected_b3_bindings, bucket_3_1_bindings)
        self.assertEqual(expected_b3_bindings, bucket_3_2_bindings)

        expected_b2_policy = {
            'bindings': [
                {
                    'role': 'roles/storage.objectAdmin',
                    'members': [
                        'user:admin@storage.com',
                    ]
                },
            ]
        }
        expected_b2_bindings = filter(None, [ # pylint: disable=bad-builtin
            iam_policy.IamPolicyBinding.create_from(b)
            for b in expected_b2_policy.get('bindings')])

        self.assertEqual(expected_b2_bindings, bucket_2_1_bindings)

    def test_retrieve_finds_bucket_policies(self):
        """IamPolicyScanner::_retrieve() finds bucket policies.

        _retrieve() is picking up bucket IAM policies (in addition to
        the organization, folder and project level ones).
        """
        policy_resources = []

        pr = mock.MagicMock()
        pr.full_name = 'organization/234/iam_policy/organization:234/'
        pr.type_name = 'iam_policy/organization:234'
        pr.name = 'organization:234'
        pr.type = 'iam_policy'
        pr.data = '{"bindings": [{"members": ["domain:gcp.work"], "role": "roles/billing.creator"}, {"members": ["user:da@gcp.work"], "role": "roles/owner"}], "etag": "BwVmVJ0OeTs="}'
        pr.parent = mock.MagicMock()
        pr.parent.type = 'organization'
        pr.parent.name = '234'
        pr.parent.full_name = 'organization/234/'
        policy_resources.append(pr)

        pr = mock.MagicMock()
        pr.full_name = 'organization/234/folder/333/iam_policy/folder:333/'
        pr.type_name = 'iam_policy/folder:333'
        pr.name = 'folder:333'
        pr.type = 'iam_policy'
        pr.data = '{"bindings": [{"members": ["user:dd@gcp.work"], "role": "roles/resourcemanager.folderEditor"}], "etag": "BwVmQ+cRxiA="}'
        pr.parent = mock.MagicMock()
        pr.parent.type = 'folder'
        pr.parent.name = '333'
        pr.parent.full_name = 'organization/234/folder/333/'
        policy_resources.append(pr)

        pr = mock.MagicMock()
        pr.full_name = 'organization/234/project/435/iam_policy/project:435/'
        pr.type_name = 'iam_policy/project:435'
        pr.name = 'project:435'
        pr.type = 'iam_policy'
        pr.data = '{"bindings": [{"members": ["user:abc@gcp.work"], "role": "roles/owner"}], "etag": "BwVlqEvec+E=", "version": 1}'
        pr.parent = mock.MagicMock()
        pr.parent.type = 'project'
        pr.parent.name = '435'
        pr.parent.full_name = 'organization/234/project/435/'
        policy_resources.append(pr)

        pr = mock.MagicMock()
        pr.full_name = 'organization/234/project/435/bucket/789/iam_policy/bucket:789/'
        pr.type_name = 'iam_policy/bucket:789'
        pr.name = 'bucket:789'
        pr.type = 'iam_policy'
        pr.data = '{"bindings": [{"members": ["projectEditor:435", "projectOwner:435"], "role": "roles/storage.legacyBucketOwner"}, {"members": ["projectViewer:435"], "role": "roles/storage.legacyBucketReader"}, {"members": ["user:ov@gmail.com"], "role": "roles/storage.objectViewer"}], "etag": "CAI=", "kind": "storage#policy", "resourceId": "projects/_/buckets/789"}'
        pr.parent = mock.MagicMock()
        pr.parent.type = 'bucket'
        pr.parent.name = '789'
        pr.parent.full_name = 'organization/234/project/435/bucket/789/'
        policy_resources.append(pr)

        mock_data_access = mock.MagicMock()
        mock_data_access.scanner_iter.return_value = policy_resources
        mock_service_config = mock.MagicMock()
        mock_service_config.model_manager = mock.MagicMock()
        mock_service_config.model_manager.get.return_value = mock.MagicMock(), mock_data_access
        self.scanner.service_config = mock_service_config

        # call the method under test.
        policy_data, resource_counts = self.scanner._retrieve()

        # we picked up the bucket IAM policy.
        self.assertEqual(1, resource_counts['bucket'])
        [(bucket, bucket_bindings)] = [
                (r, bs) for (r, _, bs) in policy_data
                if r.type == 'bucket']

        self.assertEqual('789', bucket.id)
        self.assertEqual('bucket', bucket.type)

        expected_policy = {
            'bindings': [
                {
                    'role': 'roles/storage.objectViewer',
                    'members': [
                        'user:ov@gmail.com',
                    ]
                },
            ]
        }
        expected_bindings = filter(None, [ # pylint: disable=bad-builtin
            iam_policy.IamPolicyBinding.create_from(b)
            for b in expected_policy.get('bindings')])

        self.assertEqual(expected_bindings, bucket_bindings)

    def test_retrieve_finds_billing_account_policies(self):
        """IamPolicyScanner::_retrieve() finds billing account policies.
        """
        policy_resources = []

        pr = mock.MagicMock()
        pr.full_name = 'organization/234/iam_policy/organization:234/'
        pr.type_name = 'iam_policy/organization:234'
        pr.name = 'organization:234'
        pr.type = 'iam_policy'
        pr.data = '{"bindings": [{"members": ["domain:gcp.work"], "role": "roles/billing.user"}, {"members": ["user:da@gcp.work"], "role": "roles/owner"}], "etag": "BwVmVJ0OeTs="}'
        pr.parent = mock.MagicMock()
        pr.parent.type = 'organization'
        pr.parent.name = '234'
        pr.parent.full_name = 'organization/234/'
        policy_resources.append(pr)

        pr = mock.MagicMock()
        pr.full_name = 'organization/234/billing_account/ABCD-1234/iam_policy/billing_account:ABCD-1234/'
        pr.type_name = 'iam_policy/billing_account:ABCD-1234'
        pr.name = 'billing_account:ABCD-1234'
        pr.type = 'iam_policy'
        pr.data = '{"bindings": [{"members": ["user:cfo@gcp.work"], "role": "roles/billing.admin"}, {"members": ["group:auditors@gcp.work"], "role": "roles/logging.viewer"}], "etag": "BwVmQ+cRxiA="}'
        pr.parent = mock.MagicMock()
        pr.parent.type = 'billing_account'
        pr.parent.name = 'ABCD-1234'
        pr.parent.full_name = 'organization/234/billing_account/ABCD-1234/'
        policy_resources.append(pr)

        mock_data_access = mock.MagicMock()
        mock_data_access.scanner_iter.return_value = policy_resources
        mock_service_config = mock.MagicMock()
        mock_service_config.model_manager = mock.MagicMock()
        mock_service_config.model_manager.get.return_value = mock.MagicMock(), mock_data_access
        self.scanner.service_config = mock_service_config

        # Call the method under test.
        policy_data, resource_counts = self.scanner._retrieve()

        # Check the Billing Account policy was retrieved
        self.assertEqual(1, resource_counts['billing_account'])
        [(billing_acct, billing_acct_bindings)] = [
                (r, bs) for (r, _, bs) in policy_data
                if r.type == 'billing_account']

        self.assertEqual('ABCD-1234', billing_acct.id)
        self.assertEqual('billing_account', billing_acct.type)

        expected_bindings = [
            iam_policy.IamPolicyBinding.create_from({
                'role': 'roles/billing.admin',
                'members': [
                    'user:cfo@gcp.work',
                ]
            }),
            iam_policy.IamPolicyBinding.create_from({
                'role': 'roles/logging.viewer',
                'members': [
                    'group:auditors@gcp.work',
                ]
            })]

        self.assertEqual(expected_bindings, billing_acct_bindings)

    def test_retrieve_finds_dataset_policies(self):
        """IamPolicyScanner::_retrieve() finds dataset policies.
        """
        policy_resources = []

        pr = mock.MagicMock()
        pr.full_name = 'organization/234/iam_policy/organization:234/'
        pr.type_name = 'iam_policy/organization:234'
        pr.name = 'organization:234'
        pr.type = 'iam_policy'
        pr.data = '{"bindings": [{"members": ["domain:gcp.work"], "role": "roles/billing.user"}, {"members": ["user:da@gcp.work"], "role": "roles/owner"}], "etag": "BwVmVJ0OeTs="}'
        pr.parent = mock.MagicMock()
        pr.parent.type = 'organization'
        pr.parent.name = '234'
        pr.parent.full_name = 'organization/234/'
        policy_resources.append(pr)

        pr = mock.MagicMock()
        pr.full_name = 'organization/234/project/435/iam_policy/project:435/'
        pr.type_name = 'iam_policy/project:435'
        pr.name = 'project:435'
        pr.type = 'iam_policy'
        pr.data = '{"bindings": [{"members": ["user:abc@gcp.work"], "role": "roles/owner"}], "etag": "BwVlqEvec+E=", "version": 1}'
        pr.parent = mock.MagicMock()
        pr.parent.type = 'project'
        pr.parent.name = '435'
        pr.parent.full_name = 'organization/234/project/435/'
        policy_resources.append(pr)

        pr = mock.MagicMock()
        pr.full_name = 'organization/234/project/435/dataset/proj-1:dataset-1-1/iam_policy/dataset:proj-1:dataset-1-1/'
        pr.type_name = 'iam_policy/dataset:proj-1:dataset-1-1'
        pr.name = 'dataset:proj-1:dataset-1-1'
        pr.type = 'iam_policy'
        pr.data = '{"bindings": [{"members": ["user:cfo@gcp.work"], "role": "roles/bigquery.dataeditor"}], "etag": "abc123="}'
        pr.parent = mock.MagicMock()
        pr.parent.type = 'dataset'
        pr.parent.name = 'proj-1:dataset-1-1'
        pr.parent.full_name = 'organization/234/project/435/dataset/proj-1:dataset-1-1'
        policy_resources.append(pr)

        mock_data_access = mock.MagicMock()
        mock_data_access.scanner_iter.return_value = policy_resources
        mock_service_config = mock.MagicMock()
        mock_service_config.model_manager = mock.MagicMock()
        mock_service_config.model_manager.get.return_value = mock.MagicMock(), mock_data_access
        self.scanner.service_config = mock_service_config

        # Call the method under test.
        policy_data, resource_counts = self.scanner._retrieve()

        # Check the Dataset policy was retrieved
        self.assertEqual(1, resource_counts['dataset'])
        [(dataset, dataset_bindings)] = [
                (r, bs) for (r, _, bs) in policy_data
                if r.type == 'dataset']

        self.assertEqual('proj-1:dataset-1-1', dataset.id)
        self.assertEqual('dataset', dataset.type)

        expected_bindings = [
            iam_policy.IamPolicyBinding.create_from({
                'role': 'roles/bigquery.dataeditor',
                'members': [
                    'user:cfo@gcp.work',
                ]
            })]

        self.assertEqual(expected_bindings, dataset_bindings)


if __name__ == '__main__':
    unittest.main()
