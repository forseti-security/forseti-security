from google.apputils import app
from concurrent import futures
import time
import grpc

from google.cloud.security.iam.playground import playground_pb2
from google.cloud.security.iam.playground import playground_pb2_grpc

class Playgrounder(playground_pb2_grpc.PlaygroundServicer):

	def Ping(self, request, context):
		return playground_pb2.PingReply(data=request.data)

	def SetIamPolicy(self, request, context):
		return playground_pb2.SetIamPolicyReply()

	def GetIamPolicy(self, request, context):
		return playground_pb2.GetIamPolicyReply()

	def CheckIamPolicy(self, request, context):
		return playground_pb2.CheckIamPolicyReply()

	def AddMember(self, request, context):
		return playground_pb2.AddMemberReply()

	def CreateMember(self, request, context):
		return playground_pb2.CreateMemberReply()

	def DeleteMember(self, request, context):
		return playground_pb2.DeleteMemberReply()

	def AddResource(self, request, context):
		return playground_pb2.AddResourceReply()

	def DeleteResource(self, request, context):
		return playground_pb2.DeleteResourceReply()

def serve(endpoint='[::]:50051', max_workers=10, wait_shutdown_secs=3):
	server = grpc.server(futures.ThreadPoolExecutor(max_workers))
	playground_pb2_grpc.add_PlaygroundServicer_to_server(Playgrounder(), server)
	server.add_insecure_port(endpoint)
	server.start()
	while True:
		try:
			time.sleep(1)
		except KeyboardInterrupt:
			server.stop(wait_shutdown_secs).wait()
			return

def main(argv):
	serve()

if __name__ == "__main__":
	app.run()

