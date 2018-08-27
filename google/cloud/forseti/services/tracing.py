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

"""Forseti gRPC tracing setup."""

from opencensus.trace.tracer import Tracer
from opencensus.trace.samplers import always_on
from opencensus.trace.exporters import stackdriver_exporter, file_exporter
from opencensus.trace.exporters.transports import background_thread
from opencensus.trace.ext.grpc import client_interceptor, server_interceptor

from google.cloud.forseti.common.util import logger

LOGGER = logger.get_logger(__name__)


def trace_client_interceptor(endpoint):
    """Intercept gRPC calls on client-side and add tracing information
    to the request.

    Args:
        endpoint (str): The gRPC channel endpoint (e.g: localhost:5001).

    Returns:
        OpenCensusClientInterceptor: a gRPC client-side interceptor.
    """
    exporter = setup_exporter()
    tracer = Tracer(exporter=exporter)
    return client_interceptor.OpenCensusClientInterceptor(
        tracer,
        host_port=endpoint)


def trace_server_interceptor():
    """Intercept gRPC calls on server-side and add tracing information
    to the request.

    Returns:
        OpenCensusServerInterceptor: a gRPC server-side interceptor.
    """

    exporter = setup_exporter()
    sampler = always_on.AlwaysOnSampler()
    return server_interceptor.OpenCensusServerInterceptor(
        sampler,
        exporter)


def setup_exporter():
    """Setup an exporter for traces.

    The default exporter is the StackdriverExporter. If it fails to initialize,
    the FileExporter will be used instead.

    Returns:
        `StackdriverExporter`: A Stackdriver exporter.
        `FileExporter`: A file exporter.
    """
    try:
        exporter = stackdriver_exporter.StackdriverExporter(
            transport=background_thread.BackgroundThreadTransport)
        LOGGER.info(
            'StackdriverExporter set up successfully for project %s.',
            exporter.project_id)
    except Exception as e:
        LOGGER.exception(e)
        LOGGER.warning('StackdriverExporter set up failed. Using FileExporter.')
        exporter = file_exporter.FileExporter(
            transport=background_thread.BackgroundThreadTransport)
        LOGGER.info(
            'FileExporter set up successfully. Writing to file: %s.',
            exporter.file_name)
    return exporter
