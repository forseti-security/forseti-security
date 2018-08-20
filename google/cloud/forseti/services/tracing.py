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
from opencensus.trace.samplers.always_on import AlwaysOnSampler
from opencensus.trace.exporters.stackdriver_exporter import StackdriverExporter
from opencensus.trace.ext.grpc.client_interceptor import OpenCensusClientInterceptor
from opencensus.trace.ext.grpc.server_interceptor import OpenCensusServerInterceptor

def trace_client_interceptor(endpoint):
    """Intercept gRPC calls on client-side and add tracing information
    to the request.
    
    Args:
        endpoint (str): The gRPC channel endpoint (e.g: localhost:5001).

    Returns:
        OpenCensusClientInterceptor: a gRPC client-side interceptor.
    """
    exporter = StackdriverExporter()
    tracer = Tracer(exporter=exporter)
    return OpenCensusClientInterceptor(
            tracer,
            host_port=endpoint)

def trace_server_interceptor():
    """Intercept gRPC calls on server-side and add tracing information
    to the request.
    
    Returns:
        OpenCensusServerInterceptor: a gRPC server-side interceptor.
    """
    exporter = StackdriverExporter()
    sampler = AlwaysOnSampler()
    return OpenCensusServerInterceptor(
            sampler,
            exporter)
