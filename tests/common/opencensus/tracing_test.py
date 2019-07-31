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

"""Tests for tracing."""

import json
import unittest.mock as mock
import unittest

from google.cloud.forseti.common.opencensus import tracing

from tests.unittest_utils import ForsetiTestCase


class StackdriverExporter(object):
    def __init__(self, transport):
        self.transport = transport


class TracingTest(ForsetiTestCase):
    """Test Tracing resource."""

    def setUp(self):
        if not tracing.OPENCENSUS_ENABLED:
            self.skipTest('Package `opencensus` not installed.')

    @mock.patch('opencensus.trace.ext.grpc.client_interceptor.OpenCensusClientInterceptor')
    def test_create_client_interceptor(self, mock_client_interceptor):
        tracing.create_client_interceptor('localhost')
        self.assertTrue(mock_client_interceptor.called)

    @mock.patch('opencensus.trace.ext.grpc.server_interceptor.OpenCensusServerInterceptor')
    @mock.patch('google.cloud.forseti.common.opencensus.tracing.trace_integrations')
    def test_trace_create_server_interceptor_without_extras(self, mock_libs, mock_server_interceptor):
        tracing.create_server_interceptor(extras=False)
        self.assertFalse(mock_libs.called)
        self.assertTrue(mock_server_interceptor.called)

    @mock.patch('opencensus.trace.ext.grpc.server_interceptor.OpenCensusServerInterceptor')
    @mock.patch('google.cloud.forseti.common.opencensus.tracing.trace_integrations')
    def test_trace_create_server_interceptor_with_extras(self, mock_libs, mock_server_interceptor):
        tracing.create_server_interceptor(extras=True)
        self.assertTrue(mock_libs.called)
        self.assertTrue(mock_server_interceptor.called)

    @mock.patch(
        'opencensus.trace.exporters.stackdriver_exporter.StackdriverExporter',
        spec=StackdriverExporter)
    def test_create_exporter(self, mock_stackdriver_exporter):
        mock_stackdriver_exporter.return_value.project_id = '12345'
        e = tracing.create_exporter()
        exporter_cls = e.__class__.__name__
        self.assertTrue(mock_stackdriver_exporter.called)
        self.assertEqual(exporter_cls, "StackdriverExporter")

    @mock.patch(
        'opencensus.trace.exporters.stackdriver_exporter.StackdriverExporter',
        side_effect=Exception())
    def test_create_exporter_default_fail(self, mock_stackdriver_exporter):
        e = tracing.create_exporter()
        exporter_cls = e.__class__.__name__
        self.assertEqual(exporter_cls, "FileExporter")

    def test_trace_integrations(self):
        integrated_libraries = tracing.trace_integrations()
        self.assertEqual(integrated_libraries, tracing.DEFAULT_INTEGRATIONS)


if __name__ == '__main__':
    unittest.main()
