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
from google.cloud.forseti.common.util import logger

LOGGER = logger.get_logger(__name__)
DEFAULT_INTEGRATIONS = ['requests', 'sqlalchemy']

try:
    from opencensus.common.transports import async as async_
    from opencensus.trace import config_integration
    from opencensus.trace import execution_context
    from opencensus.trace.exporters import file_exporter
    from opencensus.trace.exporters import stackdriver_exporter
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
    sampler = always_on.AlwaysOnSampler()
    if extras:
        trace_integrations()
    interceptor = server_interceptor.OpenCensusServerInterceptor(
        sampler,
        exporter)
    LOGGER.debug(execution_context.get_opencensus_tracer().span_context)
    return interceptor


def trace_integrations(integrations=None):
    """Add tracing to supported OpenCensus integration libraries.

    Args:
        integrations (list): A list of integrations to trace.

    Returns:
        list: The integrated libraries names. The return value is used only for
            testing.
    """
    integrations = integrations or DEFAULT_INTEGRATIONS
    tracer = execution_context.get_opencensus_tracer()
    integrated_libraries = config_integration.trace_integrations(
        integrations,
        tracer)
    LOGGER.info('Tracing integration libraries: %s', integrated_libraries)
    LOGGER.debug(tracer.span_context)
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
    transport = transport or async_.AsyncTransport
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
    """Start a span.

    Args:
        tracer (opencensus.trace.tracer.Tracer): OpenCensus tracer object.
        module (str): The module name.
        function (str): The function name.
        kind (opencensus.trace.span.SpanKind): The span kind.
            Default: `SpanKind.SERVER`.
    """
    if tracer is None:
        LOGGER.debug('No tracer found, cannot do `start_span`.')
        return

    span_name = '[{}] {}'.format(module, function)
    span = tracer.start_span(name=span_name)
    span.span_kind = kind or SpanKind.SERVER
    set_attributes(tracer, module=module, function=function)
    LOGGER.debug('%s.%s: %s', module, function, tracer.span_context)


def end_span(tracer, **kwargs):
    """End a span.

    Args:
        tracer (opencensus.trace.tracer.Tracer): OpenCensus tracer object.
        kwargs (dict): A set of attributes to set to the current span.
    """
    if tracer is None:
        LOGGER.debug('No tracer found, cannot do `end_span`.')
        return

    if tracer.current_span() is None:
        LOGGER.debug('No current span found, cannot do `end_span`.')
        return

    set_attributes(tracer, **kwargs)
    LOGGER.debug(tracer.span_context)
    tracer.end_span()


# pylint: disable=broad-except
def set_attributes(tracer, **kwargs):
    """Set current span attributes.

    Args:
        tracer (opencensus.trace.tracer.Tracer): OpenCensus tracer object.
        kwargs (dict): A set of attributes to set to the current span.
    """
    if tracer.current_span() is None:
        LOGGER.debug("No current span found, cannot do `set_attributes`")
        return

    for key, value in kwargs.items():
        tracer.add_attribute_to_current_span(key, value)


def get_tracer(inst=None, attr=None):
    """Get a tracer from the current context.

    This function will get a tracer using different methods with the following
    logic.

    If `inst` is passed (an instance of a class), the tracer will be fetched
    in the following order of preference:

    * from the instance attribute defined by `attr` (if passed).
    * from a list of default attributes (see `default_attribute` variable).
    * from OpenCensus context.

    If `inst` is not passed, we simply get the tracer from the OpenCensus
    context.

    Args:
        inst (Object): An instance of a class.
        attr (str): The attribute to get / set the tracer from / to.

    Returns:
        tracer(opencensus.trace.Tracer): The tracer to be used.
    """
    default_attributes = ['config.tracer', 'service_config.tracer', 'tracer']
    tracer = None
    method = ''
    if OPENCENSUS_ENABLED:

        # If working with an instance of a class (and not merely a function),
        # we get the tracer from one of the instance attributes.
        if inst is not None:

            # Get tracer from attribute `attr` passed.
            if attr is not None:
                tracer = rgetattr(inst, attr, None)
                method = 'from attribute (%s)' % attr

            # Get tracer from default attributes.
            if tracer is None:
                for _ in default_attributes:
                    tracer = rgetattr(inst, _, None)
                    if tracer is not None:
                        method = 'from default_attribute (%s)' % _
                        break

        # Get tracer from OpenCensus context.
        if tracer is None:
            tracer = execution_context.get_opencensus_tracer()
            if inst is not None:
                for _ in default_attributes:
                    try:
                        rsetattr(inst, _, tracer)
                        method += ' + set to attribute %s' % _
                        break
                    except Exception:
                        pass

            # If working with an instance of a class, set tracer to the proper
            # instance attribute (either the passed `attr` or one of the default
            # attributes).
            if inst is not None:
                attributes = [attr] if attr is not None else default_attributes
                for _ in attributes:
                    try:
                        rsetattr(inst, _, tracer)
                        method += ' + set to attribute %s' % _
                        break
                    except AttributeError:
                        pass

        LOGGER.info('Tracer @ %s [%s] : %s', inst, method, tracer.span_context)

    return tracer


def traced(methods=None):
    """Class decorator.

    Args:
        methods (list): If set, the decorator will trace those class methods.
                        If unset, trace all class methods.

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
            to_trace = cls_methods
        else:
            to_trace = [m for m in cls_methods if m[0] in methods]

        # Decorate each of the methods to be traced.
        for name, func in to_trace:
            if name != '__init__':  # never trace __init__
                setattr(cls, name, trace(func))

        return cls

    return wrapper


def trace(func):
    """Method decorator to trace a function.

    Args:
        func (func): Function to be traced.

    Returns:
        func: Decorated function.
    """
    def wrapper(*args, **kwargs):
        """Wrapper method.

        Args:
            *args: Argument list passed to the method.
            **kwargs: Argument dict passed to the method.

        Returns:
            func: Decorated function.
        """
        if OPENCENSUS_ENABLED:
            # If the decorator is applied on a class method, extract the 'self'
            # attribute from the method arguments to get / set tracer as an
            # instance attribute.
            _self = args[0] if inspect.ismethod(func) else None

            # Get the most appropriate tracer
            tracer = get_tracer(_self)

            # If the decorator is applied to a standard function, and the
            # function definition has a 'tracer' argument, set the tracer as
            # part of the function `kwargs` (if the tracer is not passed
            # directly to it).
            if _self is None and 'tracer' in kwargs:
                kwargs['tracer'] = kwargs.get('tracer', tracer)

            # Start a new OpenCensus span.
            start_span(
                tracer,
                func.__module__.split('.')[-1],
                func.__name__)

        # Execute the traced method.
        # If any exception occurs, record exception in the current span and
        # re-raise.
        # The 'finally' block makes sure we always call `end_span` no matter if
        # an exception happened or not.
        try:
            return func(*args, **kwargs)
        except Exception as e:
            if OPENCENSUS_ENABLED:
                error_str = "{}:{}".format(type(e).__name__, str(e))
                set_attributes(tracer, error=error_str, success=False)
            raise e
        finally:
            if OPENCENSUS_ENABLED:
                end_span(tracer)

    return wrapper


def rsetattr(obj, attr, val):
    """Set nested attribute in object.

    Args:
        obj (Object): An instance of a class.
        attr (str): The attribute to set the tracer to.
        val (opencensus.trace.Tracer): The tracer to set attr to.

    Returns:
        None: Return value of `setattr`.
    """

    pre, _, post = attr.rpartition('.')
    return setattr(rgetattr(obj, pre) if pre else obj, post, val)


def rgetattr(obj, attr, *args):
    """Get nested attribute from object.

    Args:
        obj (Object): An instance of a class.
        attr (str): The attribute to get the tracer from.
        *args: Argument list passed to a function.

    Returns:
        object: Fetched attribute.
    """
    def _getattr(obj, attr):
        """Get attributes in object.

        Args:
            obj (Object): An instance of a class.
            attr (str): The nested attribute to get.

        Returns:
            object: Return value of `getattr`.
        """
        return getattr(obj, attr, *args)
    return functools.reduce(_getattr, [obj] + attr.split('.'))
