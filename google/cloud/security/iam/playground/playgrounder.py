
import playground_pb2

class Playgrounder():
    def __init__(self, config, sessionCreator=None):
        self.sessionCreator = sessionCreator
        self.config = config

    def SetIamPolicy(self, model, resource, policy):
        return playground_pb2.SetIamPolicyReply()

    def GetIamPolicy(self, model, resource):
        return playground_pb2.GetIamPolicyReply()

    def CheckIamPolicy(self, model , resource, permission, identity):
        return playground_pb2.CheckIamPolicyReply()

if __name__ == "__main__":
    class DummyConfig:
        def runInBackground(self, function):
            function()
            
    e = Playgrounder(config=DummyConfig())