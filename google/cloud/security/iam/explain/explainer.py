import dao

def createScenario():
    session = dao.createSession()
    dao.createScenario(session)
    return session

class Explainer():
    def __init__(self, sessionCreator=createScenario):
        self.sessionCreator = sessionCreator

    def GetAccessByResources(self, resource_name, permission_names, expand_groups):
        session = self.sessionCreator()
        members = dao.explainHasAccessToResource(session,
                                                 resource_name,
                                                 permission_names,
                                                 expand_groups)
        return members

    def GetAccessByMembers(self, request, context):
        raise NotImplementedError()

    def GetPermissionsByRoles(self, request, context):
        raise NotImplementedError()
