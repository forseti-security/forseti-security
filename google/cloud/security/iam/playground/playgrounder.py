import google.cloud.security.iam.dao
import playground_pb2

class Playgrounder():
    def __init__(self, config):
        self.config = config

    def SetIamPolicy(self, model_name, resource, policy):
        return playground_pb2.SetIamPolicyReply()

    def GetIamPolicy(self, model_name, resource):
        return playground_pb2.GetIamPolicyReply()

    def CheckIamPolicy(self, model_name, resource, permission, identity):
        return playground_pb2.CheckIamPolicyReply()

    def AddGroupMember(self, model_name, member_name, member_type, parent_names):
        model_manager = self.config.model_manager
        session_creator, data_access = model_manager.get(model_name)
        session = session_creator()
        return data_access.addGroupMember(session, member_name, member_type, parent_names)

    def DelGroupMember(self, model_name, member_name, parent_name, only_delete_relationship):
        model_manager = self.config.model_manager
        session_creator, data_access = model_manager.get(model_name)
        session = session_creator()
        return data_access.delGroupMember(session, member_name, parent_name, only_delete_relationship)

    def ListGroupMembers(self, model_name, member_name_prefix):
        model_manager = self.config.model_manager
        session_creator, data_access = model_manager.get(model_name)
        session = session_creator()
        return data_access.listGroupMembers(session, member_name_prefix)

    def DelResource(self, model_name, full_resource_name):
        model_manager = self.config.model_manager
        session_creator, data_access = model_manager.get(model_name)
        session = session_creator()
        data_access.delResourceByName(session, full_resource_name)
        session.commit()

    def AddResource(self, model_name, full_resource_name, resource_type, no_require_parent):
        model_manager = self.config.model_manager
        session_creator, data_access = model_manager.get(model_name)
        session = session_creator()
        data_access.addResourceByName(session, full_resource_name, resource_type, no_require_parent)
        session.commit()

    def ListResources(self, model_name, full_resource_name_prefix):
        model_manager = self.config.model_manager
        session_creator, data_access = model_manager.get(model_name)
        session = session_creator()
        return data_access.listResourcesByPrefix(session, full_resource_name_prefix)
    
    def DelRole(self, model_name, role_name):
        model_manager = self.config.model_manager
        session_creator, data_access = model_manager.get(model_name)
        session = session_creator()
        data_access.delRoleByName(session, role_name)
        session.commit()

    def AddRole(self, model_name, role_name, permission_names):
        model_manager = self.config.model_manager
        session_creator, data_access = model_manager.get(model_name)
        session = session_creator()
        data_access.addRoleByName(session, role_name, permission_names)
        session.commit()

    def ListRoles(self, model_name, role_name_prefix):
        model_manager = self.config.model_manager
        session_creator, data_access = model_manager.get(model_name)
        session = session_creator()
        return data_access.listRolesByPrefix(session, role_name_prefix)

if __name__ == "__main__":
    class DummyConfig:
        def runInBackground(self, function):
            function()
            
    e = Playgrounder(config=DummyConfig())