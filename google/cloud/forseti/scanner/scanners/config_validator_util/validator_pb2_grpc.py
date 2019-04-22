from __future__ import absolute_import
# Generated by the gRPC Python protocol compiler plugin. DO NOT EDIT!
import grpc

from . import validator_pb2 as validator__pb2


class ValidatorStub(object):
  # missing associated documentation comment in .proto file
  pass

  def __init__(self, channel):
    """Constructor.

    Args:
      channel: A grpc.Channel.
    """
    self.AddData = channel.unary_unary(
        '/validator.Validator/AddData',
        request_serializer=validator__pb2.AddDataRequest.SerializeToString,
        response_deserializer=validator__pb2.AddDataResponse.FromString,
        )
    self.Audit = channel.unary_unary(
        '/validator.Validator/Audit',
        request_serializer=validator__pb2.AuditRequest.SerializeToString,
        response_deserializer=validator__pb2.AuditResponse.FromString,
        )
    self.Reset = channel.unary_unary(
        '/validator.Validator/Reset',
        request_serializer=validator__pb2.ResetRequest.SerializeToString,
        response_deserializer=validator__pb2.ResetResponse.FromString,
        )


class ValidatorServicer(object):
  # missing associated documentation comment in .proto file
  pass

  def AddData(self, request, context):
    """AddData adds GCP resource metadata to be audited later.
    """
    context.set_code(grpc.StatusCode.UNIMPLEMENTED)
    context.set_details('Method not implemented!')
    raise NotImplementedError('Method not implemented!')

  def Audit(self, request, context):
    """Audit checks the GCP resource metadata that has been added via AddData to determine if any of the constraint is violated.
    """
    context.set_code(grpc.StatusCode.UNIMPLEMENTED)
    context.set_details('Method not implemented!')
    raise NotImplementedError('Method not implemented!')

  def Reset(self, request, context):
    """Reset clears previously added data from the underlying query evaluation engine.
    """
    context.set_code(grpc.StatusCode.UNIMPLEMENTED)
    context.set_details('Method not implemented!')
    raise NotImplementedError('Method not implemented!')


def add_ValidatorServicer_to_server(servicer, server):
  rpc_method_handlers = {
      'AddData': grpc.unary_unary_rpc_method_handler(
          servicer.AddData,
          request_deserializer=validator__pb2.AddDataRequest.FromString,
          response_serializer=validator__pb2.AddDataResponse.SerializeToString,
      ),
      'Audit': grpc.unary_unary_rpc_method_handler(
          servicer.Audit,
          request_deserializer=validator__pb2.AuditRequest.FromString,
          response_serializer=validator__pb2.AuditResponse.SerializeToString,
      ),
      'Reset': grpc.unary_unary_rpc_method_handler(
          servicer.Reset,
          request_deserializer=validator__pb2.ResetRequest.FromString,
          response_serializer=validator__pb2.ResetResponse.SerializeToString,
      ),
  }
  generic_handler = grpc.method_handlers_generic_handler(
      'validator.Validator', rpc_method_handlers)
  server.add_generic_rpc_handlers((generic_handler,))
