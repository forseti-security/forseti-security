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
"""Tests the email inventory snapshot pipeline."""

from datetime import datetime

import mock

from google.cloud.security.common.gcp_type import iam_policy
from google.cloud.security.common.gcp_type import resource
from google.cloud.security.notifier.pipelines import email_scanner_summary_pipeline
from google.cloud.security.scanner.audit import rules as audit_rules
from tests.unittest_utils import ForsetiTestCase


class EmailInventorySnapshotSummaryPipelineTest(ForsetiTestCase):
    """Tests for the email_inventory_snapshot_summary_pipeline."""
    
    def test_can_compose_scanner_summary(self):
        """Test that the scan summary is built correctly."""
        email_pipeline = (
            email_scanner_summary_pipeline.EmailScannerSummaryPipeline(
                111111))

        members = [iam_policy.IamPolicyMember.create_from(u)
            for u in ['user:a@b.c', 'group:g@h.i', 'serviceAccount:x@y.z']
        ]
        all_violations = [
            audit_rules.RuleViolation(
                resource_type='organization',
                resource_id='abc111',
                rule_name='Abc 111',
                rule_index=0,
                violation_type=audit_rules.VIOLATION_TYPE['whitelist'],
                role='role1',
                members=tuple(members)),
            audit_rules.RuleViolation(
                resource_type='project',
                resource_id='def222',
                rule_name='Def 123',
                rule_index=1,
                violation_type=audit_rules.VIOLATION_TYPE['blacklist'],
                role='role2',
                members=tuple(members)),
        ]
        total_resources = {
            resource.ResourceType.ORGANIZATION: 1,
            resource.ResourceType.PROJECT: 1,
        }

        actual = email_pipeline._compose(all_violations, total_resources)

        expected_summaries = {
            resource.ResourceType.ORGANIZATION: {
                'pluralized_resource_type': 'Organizations',
                'total': 1,
                'violations': {
                    'abc111': len(members)
                }
            },
            resource.ResourceType.PROJECT: {
                'pluralized_resource_type': 'Projects',
                'total': 1,
                'violations': {
                    'def222': len(members)
                }
            },
        }
        expected_totals = sum(
            [v for t in expected_summaries.values()
            for v in t['violations'].values()])
        expected = (expected_totals, expected_summaries)

        self.assertEqual(expected, actual)
