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
from concurrent import futures
from multiprocessing import pool
import threading
from google.cloud.forseti.common.util import logger

LOGGER = logger.get_logger(__name__)
logger.get_logger('opencensus').setLevel(logging.DEBUG)  # set debug level for opencensus
DEFAULT_INTEGRATIONS = ['requests', 'sqlalchemy', 'httplib']

try:
    from opencensus.common.runtime_context import RuntimeContext
    from opencensus.common.transports.async_ import AsyncTransport
    from opencensus.ext.grpc import client_interceptor, server_interceptor
    from opencensus.ext.stackdriver import trace_exporter as stackdriver_exporter
    from opencensus.ext.threading.trace import (
        wrap_threading_start, wrap_threading_run, wrap_submit, wrap_apply_async)
    from opencensus.trace import config_integration
    from opencensus.trace import execution_context
    from opencensus.trace import file_exporter
    from opencensus.trace.tracer import Tracer
    from opencensus.trace.samplers import AlwaysOnSampler
    from opencensus.trace.span import SpanKind
    LOGGER.info('Tracing dependencies successfully imported.')
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
    LOGGER.info(f"Tracing interceptor created.")
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
    LOGGER.info(f"Tracing libraries: {integrated_libraries}")
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


def traced(methods=None, attr=None):
    """Class decorator to enable automatic tracing on designated class methods.

    Args:
        methods (list, optional): If set, the decorator will trace those class
            methods. Otherwise, trace all class methods.
        attr (str, optional): If the tracer was passed explicitely to the class
            in an attribute, get it from there.

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
        # Adds `self.tracer` in class to give access to the tracer from within.
        if OPENCENSUS_ENABLED:
            for name, func in to_trace:
                if name == '__init__': # __init__ decorator to add tracer as instance attribute
                    decorator = trace_init(attr=attr)
                else:
                    decorator = trace()
                setattr(cls, name, decorator(func))
        return cls
    return wrapper


def trace_init(attr=None):
    """Method decorator for a class's __init__ method. Set `self.tracer` (either
    from instance kwargs, attribute, or execution context).

    Args:
        attr (str, optional): If the tracer was passed explicitely to the class
            in an attribute, get it from there.

    Returns:
        func: Decorated function.
    """
    def outer_wrapper(init):
        @functools.wraps(init)
        def inner_wrapper(self, *args, **kwargs):
            cls_name = self.__class__.__name__
            LOGGER.info(f"Decorating {cls_name}")
            init(self, *args, **kwargs)

            if OPENCENSUS_ENABLED:
                if 'tracer' in kwargs:
                    # If `tracer` is passed explicitely to our class at __init__,
                    # we use that tracer.
                    LOGGER.info(f"Tracing - {cls_name}.__init__ - set tracer from kwargs")
                    self.tracer = kwargs['tracer']
                elif attr is not None:
                    # If `attr` is passed to this decorator, then get the tracer from
                    # the instance attribute.
                    LOGGER.info(f"Tracing - {cls_name}.__init__ - set tracer from class attribute {name}")
                    self.tracer = rgetattr(self, name)
                else:
                    # Otherwise, get tracer from current execution context.
                    LOGGER.info(f"Tracing - {cls_name}.__init__ - set tracer from execution context")
                    self.tracer = execution_context.get_opencensus_tracer()
                LOGGER.info(f"Tracing - {cls_name}.__init__ - context: {self.tracer.span_context}")
        return inner_wrapper
    return outer_wrapper


def trace(attr=None):
    """Method decorator to trace a class method or a function.

    Returns:
        func: Decorated function (or class method).
    """
    def outer_wrapper(func):
        """Outer wrapper.

        Args:
            func (func): Function to trace.

        Returns:
            func: Decorated function (or class method).
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
            if not OPENCENSUS_ENABLED:
                if inspect.ismethod(func):
                    args[0].tracer = None  # fix bug where tracer is not defined
                return func(*args, **kwargs)

            # Build span name from function info and fetch appropriate tracer
            module = func.__module__.split('.')[-1]
            fname = func.__name__

            # If the function is a class method, get the tracer from the
            # 'tracer' instance attribute. If it's a standard function, get
            # the tracer from the 'tracer' kwargs, and if it's empty get tracer
            # from the OpenCensus context.
            ctx_tracer = execution_context.get_opencensus_tracer()
            if inspect.ismethod(func):
                span_name = f'{module}.{fname}'
                _self = args[0]
                tracer = getattr(_self, 'tracer', ctx_tracer)
                _self.tracer = tracer
            else:
                span_name = f'{fname}'
                tracer = kwargs.get('tracer') or ctx_tracer

            LOGGER.info(f"Tracing - {span_name} - Context: {tracer.span_context}")

            # Trace our function
            with tracer.span(name=span_name) as span:

                # If the method has a `tracer` argument, pass it there
                # this will enable to start sub-spans within the target function.
                if 'tracer' in kwargs:
                    LOGGER.info(f"Tracing - {span_name} - push tracer object into `tracer` kwarg")
                    kwargs['tracer'] = tracer

                return func(*args, **kwargs)

        return inner_wrapper
    return outer_wrapper


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


def monkey_patch_multiprocessing():
    LOGGER.info("Monkeypatching `multiprocessing` library to trace methods.")

    # Wrap the threading start function
    start_func = getattr(threading.Thread, "start")
    setattr(
        threading.Thread, start_func.__name__, wrap_threading_start(start_func)
    )

    # Wrap the threading run function
    run_func = getattr(threading.Thread, "run")
    setattr(threading.Thread, run_func.__name__, wrap_threading_run(run_func))

    # Wrap the threading run function
    apply_async_func = getattr(pool.Pool, "apply_async")
    setattr(
        pool.Pool,
        apply_async_func.__name__,
        wrap_apply_async(apply_async_func),
    )

    # Wrap the threading run function
    submit_func = getattr(futures.ThreadPoolExecutor, "submit")
    setattr(
        futures.ThreadPoolExecutor,
        submit_func.__name__,
        wrap_submit(submit_func),
    )
