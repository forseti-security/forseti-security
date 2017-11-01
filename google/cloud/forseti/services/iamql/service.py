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

""" IAMQL gRPC service. """

from google.protobuf import any_pb2
from google.cloud.security.iam.iamql import iamql_pb2
from google.cloud.security.iam.iamql import iamql_pb2_grpc
from google.cloud.security.iam.iamql import iamql
from google.cloud.security.iam.utils import autoclose_stream

import numbers

# TODO: The next editor must remove this disable and correct issues.
# pylint: disable=missing-type-doc,missing-return-type-doc,missing-return-doc
# pylint: disable=missing-param-doc,missing-yield-doc
# pylint: disable=missing-yield-type-doc
# pylint: disable=no-self-use


class GrpcIamQL(iamql_pb2_grpc.IamqlServicer):
    """IAMQL gRPC implementation."""

    HANDLE_KEY = "handle"

    def _get_handle(self, context):
        """Return the handle associated with the gRPC call."""

        metadata = context.invocation_metadata()
        metadata_dict = {}
        for key, value in metadata:
            metadata_dict[key] = value
        return metadata_dict[self.HANDLE_KEY]

    def __init__(self, iamql_api):
        super(GrpcIamQL, self).__init__()
        self.iamql = iamql_api

    def Ping(self, request, _):
        """Provides the capability to check for service availability."""

        return iamql_pb2.PingReply(data=request.data)

    @autoclose_stream
    def Query(self, request, context):
        """Executes a query data structure."""
        print "Query"
        raise NotImplementedError()

    @autoclose_stream
    def QueryString(self, request, context):
        """Executes a query string."""

        def iter_pb_columns(row, index):
            alias = row[index]
            obj = row[alias]

            def pack_type(value):
                type_mapping = {
                        numbers.Number: iamql_pb2.NumberValue,
                        str: iamql_pb2.StringValue,
                        unicode: iamql_pb2.StringValue,
                        bool: iamql_pb2.BooleanValue
                    }

                for py_type, pb_type in type_mapping.iteritems():
                    if isinstance(value, py_type):
                        return pb_type(value=value)
                raise TypeError(value)

            for key, value in obj.iteritems():
                any_value = any_pb2.Any()
                value_type = pack_type(value)
                any_value.Pack(value_type)
                yield iamql_pb2.Column(name='{}.{}'.format(alias, key),
                                       value=any_value)

        model_name = self._get_handle(context)
        for row in self.iamql.QueryString(model_name, request.query):
            columns = []
            index = 0
            while index in row:
                for column in iter_pb_columns(row, index):
                    columns.append(column)
                index += 1
            yield iamql_pb2.Row(columns=columns)


class GrpcIamQLFactory(object):
    """Factory class for IAMQL service gRPC interface"""

    def __init__(self, config):
        self.config = config

    def create_and_register_service(self, server):
        """Create and register the IAMQL service."""

        service = GrpcIamQL(iamql_api=iamql.IamQL(self.config))
        iamql_pb2_grpc.add_IamqlServicer_to_server(service, server)
        return service
