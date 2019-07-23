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

import functools
import inspect
import logging
from google.cloud.forseti.common.util import logger

LOGGER = logger.get_logger(__name__)
DEFAULT_INTEGRATIONS = ['requests', 'sqlalchemy', 'threading']
logging.getLogger('opencensus').setLevel(logging.DEBUG)  # set debug level for opencensus

try:
    from opencensus.common.runtime_context import RuntimeContext
    from opencensus.common.transports.async_ import AsyncTransport
    from opencensus.ext.grpc import client_interceptor, server_interceptor
    from opencensus.ext.stackdriver import trace_exporter as stackdriver_exporter
    from opencensus.trace import config_integration
    from opencensus.trace import execution_context
    from opencensus.trace import file_exporter
    from opencensus.trace.tracer import Tracer
    from opencensus.trace.samplers import AlwaysOnSampler
    from opencensus.trace.span import SpanKind
    LOGGER.debug(
        'Tracing libraries successfully installed.'
        'Tracing modules succesfully imported.')
    OPENCENSUS_ENABLED = True
except ImportError:
    LOGGER.warning(
        'Cannot enable tracing because the `opencensus` library was not '
        'found. Run `sudo pip3 install .[tracing]` to install tracing libraries.')
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
    interceptor = client_interceptor.OpenCensusClientInterceptor(
        tracer,
        host_port=endpoint)
    return interceptor


def create_server_interceptor(extras=True):
    """Create gRPC server interceptor.

    Args:
        extras (bool): If set to True, also trace integration libraries.

    Returns:
        OpenCensusServerInterceptor: a gRPC server-side interceptor.
    """

    exporter = create_exporter()
    sampler = AlwaysOnSampler()
    interceptor = server_interceptor.OpenCensusServerInterceptor(
        sampler,
        exporter)
    if extras:
        trace_integrations(DEFAULT_INTEGRATIONS)
    return interceptor


def trace_integrations(integrations):
    """Add tracing to supported OpenCensus integration libraries.

    Args:
        integrations (list): A list of integrations to trace.

    Returns:
        list: The integrated libraries names. The return value is used only for
            testing.
    """
    tracer = execution_context.get_opencensus_tracer()
    integrated_libraries = config_integration.trace_integrations(
        integrations,
        tracer)
    return integrated_libraries


def create_exporter(transport=None):
    """Create an exporter for traces.

    The default exporter is the StackdriverExporter. If it fails to initialize,
    the FileExporter will be used instead.

    Args:
        transport (opencensus.trace.common.transports.base.Transport): the
            OpenCensus transport used by the exporter to emit data.

    Returns:
        StackdriverExporter: A Stackdriver exporter.
        FileExporter: A file exporter. Default path: 'opencensus-traces.json'.
    """
    transport = transport or AsyncTransport
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

def traced(methods=None):
    """Class decorator.

    Args:
        methods (list): If set, the decorator will trace those class methods.
            Otherwise, trace all class methods.

    Returns:
        object: Decorated class.
    """
    def wrapper(cls):
        """Decorate selected class methods.

        Args:
            cls (object): Class to decorate.

        Returns:
            object: Decorated class.
        """
        # Get names of methods to be traced.
        cls_methods = inspect.getmembers(cls, inspect.ismethod)
        if methods is None:
            to_trace = cls_methods  # trace all class methods
        else:
            to_trace = [m for m in cls_methods if m[0] in methods]  # trace specified methods

        # Decorate each of the methods to be traced.
        for name, func in to_trace:
            if name != '__init__':  # never trace __init__
                decorator = trace()
                setattr(cls, name, decorator(func))

        return cls

    return wrapper

def trace():
    """Method decorator to trace a function.

    Returns:
        func: Decorated function.
    """
    def outer_wrapper(func):
        """Outer wrapper.

        Args:
            func (func): Function to trace.

        Returns:
            func: Decorated function.
        """
        @functools.wraps(func)
        def inner_wrapper(*args, **kwargs):
            """Inner wrapper.

            Args:
                *args: Argument list passed to the method.
                **kwargs: Argument dict passed to the method.

            Returns:
                func: Decorated function.

            Raises:
                Exception: Exception thrown by the decorated function (if any).
            """
            if OPENCENSUS_ENABLED:
                tracer = execution_context.get_opencensus_tracer()
                module = func.__module__.split('.')[-1]
                fname = func.__name__
                LOGGER.debug("Tracing {module}.{function}")
                LOGGER.debug("Tracing context: {tracer.span_context}")
                if inspect.ismethod(func):
                    span_name = "{module}.{fname}"
                else:
                    span_name = '{fname}'
                with tracer.span(name=span_name) as span:
                    kwargs['span'] = span
                    return func(*args, **kwargs)
            return func(*args, **kwargs)
        return inner_wrapper
    return outer_wrapper
