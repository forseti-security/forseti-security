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

"""Tests the pipeline builder."""

from google.apputils import basetest
import mock

from google.cloud.security.scanner import pipeline_builder
from tests.scanner.test_data import fake_runnable_pipelines


BASE_PATH = 'tests/scanner/test_data/'
FAKE_TIMESTAMP = '20001225T121212Z'
FAKE_GLOBAL_CONFIGS = {
    'db_host': 'foo',
    'db_user': 'bar',
    'db_name': 'baz'
}


class PipelineBuilderTest(basetest.TestCase):
    """Tests for the scanner pipeline builder test."""

    @mock.patch('google.cloud.security.scanner.scanners.iam_rules_scanner.iam_rules_engine',
                autospec=True)
    @mock.patch('google.cloud.security.scanner.scanners.cloudsql_rules_scanner.cloudsql_rules_engine',
                autospec=True)
    @mock.patch('google.cloud.security.scanner.scanners.bucket_rules_scanner.buckets_rules_engine',
                autospec=True)
    @mock.patch('google.cloud.security.scanner.scanners.bigquery_scanner.bigquery_rules_engine',
                autospec=True)
    def testAllEnabled(self,
                       mock_bigquery_rules_engine,
                       mock_bucket_rules_engine,
                       mock_cloudsql_rules_engine,
                       mock_iam_rules_engine):
        builder = pipeline_builder.PipelineBuilder(
            FAKE_GLOBAL_CONFIGS, fake_runnable_pipelines.ALL_ENABLED,
            FAKE_TIMESTAMP)
        runnable_pipelines = builder.build()
        
        self.assertEquals(4, len(runnable_pipelines))

        expected_pipelines = ['BigqueryScanner', 'BucketsAclScanner',
                              'CloudSqlAclScanner', 'IamPolicyScanner']
        for pipeline in runnable_pipelines:
            self.assertTrue(type(pipeline).__name__ in expected_pipelines)

    def testAllDisabled(self):
        builder = pipeline_builder.PipelineBuilder(
            FAKE_GLOBAL_CONFIGS, fake_runnable_pipelines.ALL_DISABLED,
            FAKE_TIMESTAMP)
        runnable_pipelines = builder.build()
        
        self.assertEquals(0, len(runnable_pipelines))

    @mock.patch('google.cloud.security.scanner.scanners.iam_rules_scanner.iam_rules_engine',
                autospec=True)
    def testOneEnabled(self, mock_iam_rules_engine):
        builder = pipeline_builder.PipelineBuilder(
            FAKE_GLOBAL_CONFIGS, fake_runnable_pipelines.ONE_ENABLED,
            FAKE_TIMESTAMP)
        runnable_pipelines = builder.build()
        
        self.assertEquals(1, len(runnable_pipelines))
        expected_pipelines = ['IamPolicyScanner']
        for pipeline in runnable_pipelines:
            self.assertTrue(type(pipeline).__name__ in expected_pipelines)

    @mock.patch('google.cloud.security.scanner.scanners.iam_rules_scanner.iam_rules_engine',
                autospec=True)
    @mock.patch('google.cloud.security.scanner.scanners.bucket_rules_scanner.buckets_rules_engine',
                autospec=True)
    def testTwoEnabled(self, mock_bucket_rules_engine, mock_iam_rules_engine):
        builder = pipeline_builder.PipelineBuilder(
            FAKE_GLOBAL_CONFIGS, fake_runnable_pipelines.TWO_ENABLED,
            FAKE_TIMESTAMP)
        runnable_pipelines = builder.build()

        self.assertEquals(2, len(runnable_pipelines))
        expected_pipelines = ['BucketsAclScanner', 'IamPolicyScanner']
        for pipeline in runnable_pipelines:
            self.assertTrue(type(pipeline).__name__ in expected_pipelines)
