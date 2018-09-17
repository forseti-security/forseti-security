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
import unittest
import mock
import parameterized
import logging
try:
    from google.cloud.forseti.common.opencensus.tracing import (
        create_client_interceptor,
        create_server_interceptor,
        create_exporter,
        trace_integrations,
        DEFAULT_INTEGRATIONS
    )
    tracing_libs = True
except ImportError:
    logging.exception('failed to import tracing libs.')
    tracing_libs = False


from tests.unittest_utils import ForsetiTestCase


class StackdriverExporter(object):
    def __init__(self, transport):
        self.transport = transport


class TracingTest(ForsetiTestCase):
    """Test Tracing resource."""

    def setUp(self):
        if not tracing_libs:
            self.skipTest('Package `opencensus` not installed.')

    @mock.patch('opencensus.trace.ext.grpc.client_interceptor.OpenCensusClientInterceptor')
    def test_create_client_interceptor(self, mock):
        create_client_interceptor('localhost')
        self.assertTrue(mock.called)

    @mock.patch('opencensus.trace.ext.grpc.server_interceptor.OpenCensusServerInterceptor')
    @mock.patch('google.cloud.forseti.common.opencensus.tracing.trace_integrations')
    def test_trace_create_server_interceptor(self, mock_libs, mock_server):
        create_server_interceptor(extras=False)
        self.assertFalse(mock_libs.called)
        self.assertTrue(mock_server.called)

    @mock.patch('opencensus.trace.ext.grpc.server_interceptor.OpenCensusServerInterceptor')
    @mock.patch('google.cloud.forseti.common.opencensus.tracing.trace_integrations')
    def test_trace_create_server_interceptor_extras(self, mock_libs, mock_server):
        create_server_interceptor(extras=True)
        self.assertTrue(mock_libs.called)
        self.assertTrue(mock_server.called)

    @mock.patch(
        'opencensus.trace.exporters.stackdriver_exporter.StackdriverExporter',
        spec=StackdriverExporter)
    def test_create_exporter(self, mock):
        e = create_exporter()
        e_class = e.__class__.__name__
        t_class = e.transport.__class__.__name__
        self.assertTrue(mock.called)
        self.assertEqual(t_class, "BackgroundThreadTransport")

    @mock.patch(
        'opencensus.trace.exporters.stackdriver_exporter.StackdriverExporter',
        side_effect=Exception())
    def test_create_exporter_default_fail(self, mock):
        e = create_exporter()
        e_class = e.__class__.__name__
        self.assertEqual(e_class, "FileExporter")

    def test_trace_integrations(self):
        integrated = trace_integrations()
        self.assertEqual(integrated, DEFAULT_INTEGRATIONS)
