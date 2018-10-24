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

"""Forseti OpenCensus gRPC tracing setup."""

from google.cloud.forseti.common.util import logger

LOGGER = logger.get_logger(__name__)
DEFAULT_INTEGRATIONS = ['requests', 'sqlalchemy', 'threading']

try:
    from opencensus.trace import config_integration
    from opencensus.trace import execution_context
    from opencensus.trace.exporters import file_exporter
    from opencensus.trace.exporters import stackdriver_exporter
    from opencensus.trace.exporters.transports import background_thread
    from opencensus.trace.ext.grpc import client_interceptor
    from opencensus.trace.ext.grpc import server_interceptor
    from opencensus.trace.samplers import always_on
    from opencensus.trace.tracer import Tracer
    from opencensus.trace.span import SpanKind
    OPENCENSUS_ENABLED = True
except ImportError:
    LOGGER.warning(
        'Cannot enable tracing because the `opencensus` library was not '
        'found. Run `pip install .[tracing]` to install tracing libraries.')
    OPENCENSUS_ENABLED = False


def create_client_interceptor(endpoint):
    """Create gRPC client interceptor.

    Args:
        endpoint (str): The gRPC channel endpoint (e.g: localhost:5001).

    Returns:
        OpenCensusClientInterceptor: a gRPC client-side interceptor.
    """
    exporter = create_exporter()
    tracer = Tracer(exporter=exporter)
    LOGGER.info("before init: %s" % tracer.span_context)
    interceptor = client_interceptor.OpenCensusClientInterceptor(
        tracer,
        host_port=endpoint)
    LOGGER.info("after init: %s" % execution_context.get_opencensus_tracer().span_context)
    return interceptor

def create_server_interceptor(extras=True):
    """Create gRPC server interceptor.

    Args:
        extras (bool): If set to True, also trace integration libraries.

    Returns:
        OpenCensusServerInterceptor: a gRPC server-side interceptor.
    """

    exporter = create_exporter()
    sampler = always_on.AlwaysOnSampler()
    if extras:
        trace_integrations()
    LOGGER.info("(before init): %s" % execution_context.get_opencensus_tracer().span_context)
    interceptor = server_interceptor.OpenCensusServerInterceptor(
        sampler,
        exporter)
    #LOGGER.info("(within tracer): %s" % interceptor.tracer)
    LOGGER.info("(after init): %s" % execution_context.get_opencensus_tracer().span_context)
    return interceptor

def trace_integrations(integrations=None):
    """Add tracing to supported OpenCensus integration libraries.

    Args:
        integrations (list): A list of integrations to trace.

    Returns:
        list: The integrated libraries names. The return value is used only for
            testing.
    """
    if integrations is None:
        integrations = DEFAULT_INTEGRATIONS
    tracer = execution_context.get_opencensus_tracer()
    integrated_libraries = config_integration.trace_integrations(
        integrations,
        tracer)
    LOGGER.info('Tracing integration libraries: %s', integrated_libraries)
    LOGGER.info(tracer.span_context)
    return integrated_libraries


def create_exporter(transport=None):
    """Create an exporter for traces.

    The default exporter is the StackdriverExporter. If it fails to initialize,
    the FileExporter will be used instead.

    Args:
        transport (opencensus.trace.exporters.transports.base.Transport): the
            OpenCensus transport used by the exporter to emit data.

    Returns:
        StackdriverExporter: A Stackdriver exporter.
        FileExporter: A file exporter. Default path: 'opencensus-traces.json'.
    """
    if transport is None:
        transport = background_thread.BackgroundThreadTransport

    try:
        exporter = stackdriver_exporter.StackdriverExporter(transport=transport)
        LOGGER.info(
            'StackdriverExporter set up successfully for project %s.',
            exporter.project_id)
        return exporter
    except Exception:  # pylint: disable=broad-except
        LOGGER.exception(
            'StackdriverExporter set up failed. Using FileExporter.')
        return file_exporter.FileExporter(transport=transport)

    
def start_span(tracer, module, function, kind=None):
    """Start a span"""
    if kind is None:
        kind = SpanKind.SERVER
    span = tracer.start_span()
    span.name = "[{}] {}".format(module, function)
    span.span_kind = kind
    tracer.add_attribute_to_current_span('module', module)
    tracer.add_attribute_to_current_span('function', function)
    return span
    
def end_span(tracer, span, **kwargs):
    """End a span. Update the span_id in SpanContext to the current
    span's parent id; update the current span; Send the span to exporter.
    """
    for k, v in kwargs.items():
        tracer.add_attribute_to_current_span(k, v)
    LOGGER.info(tracer.span_context)
    tracer.end_span()
    
def trace_decorator(func):
    """Decorator to trace a function"""

    def wrapper(*args, **kwargs):
        LOGGER.info('Before calling start_span from wrapper')
        self.start_span(*args, **kwargs)
        return_value = func(*args, **kwargs)
        LOGGER.info('return_value %s:', return_value)
        LOGGER.info('After calling start_span from wrapper')
        LOGGER.info('Before calling end_span from wrapper')
        self.end_span(*args, **kwargs)
        LOGGER.info('After calling end_span from wrapper')
        return wrapper
