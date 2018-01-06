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

"""Auditor gRPC service."""

import google.protobuf.timestamp_pb2 as timestamp

from google.cloud.forseti.services.auditor import auditor
from google.cloud.forseti.services.actions import action_engine_pb2
from google.cloud.forseti.services.auditor import auditor_pb2
from google.cloud.forseti.services.auditor import auditor_pb2_grpc
from google.cloud.forseti.services.inventory import inventory_pb2
from google.cloud.forseti.services.utils import autoclose_stream
from google.cloud.forseti.common.util import log_util


LOGGER = log_util.get_logger(__name__)

# pylint: disable=missing-type-doc,missing-return-type-doc,missing-return-doc
# pylint: disable=missing-param-doc


def audit_pb_from_object(audit):
    """Audit data to proto."""

    end_time = timestamp.Timestamp().FromDatetime(
        audit.end_time) if audit.end_time else None

    return auditor_pb2.Audit(
        id=audit.id,
        start_time=timestamp.Timestamp().FromDatetime(
            audit.start_time),
        end_time=end_time,
        status=audit.status.value,
        model=audit.model,
        messages=audit.messages)

def ruleresult_pb_from_object(rule_result):
    """RuleResult to proto."""

    return action_engine_pb2.RuleResult(
        rule_id=rule_result.rule_id,
        audit_id=rule_result.audit_id,
        resource_type_name=rule_result.resource_type_name,
        current_state=rule_result.current_state,
        expected_state=rule_result.expected_state,
        info=rule_result.info,
        result_hash=rule_result.result_hash,
        model_handle=rule_result.model_handle,
        resource_owners=rule_result.resource_owners,
        status=rule_result.status,
        recommended_actions=rule_result.actions,
        create_time=timestamp.Timestamp().FromDateTime(
            rule_result.create_time),
        modified_time=timestamp.Timestamp().FromDateTime(
            rule_result.modified_time))


class GrpcAuditor(auditor_pb2_grpc.AuditorServicer):
    """Forseti Auditor gRPC implementation."""

    HANDLE_KEY = 'handle'

    def _get_handle(self, context):
        """Return the handle associated with the gRPC call."""

        metadata = context.invocation_metadata()
        metadata_dict = {}
        for key, value in metadata:
            metadata_dict[key] = value
        return metadata_dict[self.HANDLE_KEY]

    def __init__(self, auditor_api):
        super(GrpcAuditor, self).__init__()
        self.auditor = auditor_api

    def Ping(self, request, _):
        """Provides the capability to check for service availability."""

        return auditor_pb2.PingReply(data=request.data)

    @autoclose_stream
    def Run(self, request, context):
        """Run auditor.

        Args:
            request (object): gRPC request object.
            context (object): Server context.

        Yields:
            object: Audit progress updates.
        """

        if request.model_handle:
            model_name = request.model_handle
        else:
            model_name = self._get_handle(context)
        LOGGER.info('Run auditor service with model: %s', model_name)
        config_path = request.config_path
        for progress in self.auditor.Run(config_path, model_name):
            yield inventory_pb2.Progress(
                id=progress.entity_id,
                final_message=progress.final_message,
                step=progress.step,
                warnings=progress.warnings,
                errors=progress.errors,
                last_warning=repr(progress.last_warning),
                last_error=repr(progress.last_error))

    @autoclose_stream
    def List(self, request, _):
        """List the existing audits.

        Args:
            request (object): gRPC request object.
            _ (object): unused

        Yields:
            object: Audit
        """

        for audit in self.auditor.List():
            yield audit_pb_from_object(audit)

    @autoclose_stream
    def GetResults(self, request, _):
        """Get audit results.

        Args:
            request (object): gRPC request object.
            _ (object): unused

        Yields:
            object: RuleResult
        """

        for result in self.auditor.GetResults(request.id):
            yield ruleresult_pb_from_object(result)

    def Delete(self, request, _):
        """Delete an audit."""

        audit = self.auditor.Delete(request.id)
        return auditor_pb2.DeleteReply(
            audit=audit_pb_from_object(audit))


class GrpcAuditorFactory(object):
    """Factory class for Auditor service gRPC interface"""

    def __init__(self, config):
        self.config = config

    def create_and_register_service(self, server):
        """Create and register the Forseti Auditor service."""
        service = GrpcAuditor(
            auditor_api=auditor.Auditor(self.config))
        auditor_pb2_grpc.add_AuditorServicer_to_server(service, server)
        return service
