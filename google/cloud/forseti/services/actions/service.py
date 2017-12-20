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

""" Action Engine gRPC service. """

from google.cloud.forseti.services.actions import action_engine_pb2
from google.cloud.forseti.services.actions import action_engine_pb2_grpc
from google.cloud.forseti.services.actions import action_engine


ACTION_TYPE_MAPPING = {
    'SampleAction': action_engine_pb2.Action.SampleAction,
    'BaseAction': action_engine_pb2.Action.BaseAction,
}


def action_pb_from_object(action):
    """Convert internal action data structure to protobuf.

    Args:
      action (object): An action object.

    Returns:
      object: An Action proto.
    """
    return action_engine_pb2.Action(
        action_id=action.action_id,
        type=ACTION_TYPE_MAPPING[action.type],
        triggers=action.triggers,
        config=action.config,
    )


def action_result_pb_from_object(result):
    """Convert internal action data structure to protobuf.

    Args:
      result (object): An ActionResult object.

    Returns:
      list: An ActionResult proto.
    """
    return action_engine_pb2.ActionResult(
        code=result.code,
        action_id=result.action_id,
        info=result.info,
    )


def action_results_pb_from_objects(results):
    """Convert internal action result list data structure to protobuf.

    Args:
      results (list): A list of ActionResults objects.

    Returns:
      list: A list of ActionResults protos.
    """
    action_results = []
    for result in results:
        action_results.append(action_result_pb_from_object(result))
    return action_results


class GrpcActionEngine(action_engine_pb2_grpc.ActionEngineServicer):
    """Action Engine gRPC handler."""

    def __init__(self, action_engine_api):
        """Initializes.

        Args:
          action_engine_api (object): The action engine api object.
        """
        super(GrpcActionEngine, self).__init__()
        self.action_engine = action_engine_api

    def Ping(self, request, _):
        """Ping implemented to check service availability.

        Args:
            request (object): gRPC request object.
            _ (object): Unused.

        Returns:
            object: PingReply containing echo of data.
        """

        return action_engine_pb2.PingReply(data=request.data)

    def List(self, _0, _1):
        """Lists configured actions.

        Args:
            _0 (object): Unused.
            _1 (object): Unused.

        Returns:
            object: Each action object.
        """
        return action_engine_pb2.ListResponse(actions=[
            action_pb_from_object(a) for a in self.action_engine.actions])

    def ProcessResults(self, request, _):
        """Processes RuleResults.

        Args:
            request (object): gRPC request object.
            _ (object): Unused.

        Returns:
            object: A ProcessResultsResponse proto.
        """
        results = self.action_engine.process_results(request.results)
        processed_results = []
        for rule_result, action_results in results.items():
            a_results = action_results_pb_from_objects(action_results)
            processed_result = action_engine_pb2.ProcessedResult(
                result=rule_result,
                action_results=a_results)
            processed_results.append(processed_result)
        return action_engine_pb2.ProcessResultsResponse(
            processed_results=processed_results)

class GrpcActionEngineFactory(object):
    """Factory class for Action Engine service gRPC interface."""

    def __init__(self, config):
        """Initializes.

        Args:
          config (str): A configuration string file path.
        """
        self.config = config

    def create_and_register_service(self, server):
        """Creates an action engine service and registers it.

        Args:
          server (object): Server to register service to.

        Returns:
          object: The instanciated gRPC service for action engine.
        """
        service = GrpcActionEngine(
            action_engine_api=action_engine.ActionEngine(
                self.config))
        action_engine_pb2_grpc.add_ActionEngineServicer_to_server(
            service, server)
        return service
