import dao
from importer import importer


def createScenario():
    session = dao.createSession()
    dao.createScenario(session)
    return session

class Explainer():
    def __init__(self, config, sessionCreator=createScenario):
        self.sessionCreator = sessionCreator
        self.config = config

    def GetAccessByResources(self, resource_name, permission_names, expand_groups):
        session = self.sessionCreator()
        members = dao.explainHasAccessToResource(session,
                                                 resource_name,
                                                 permission_names,
                                                 expand_groups)
        return members
    
    def CreateModel(self, source):
        session = self.sessionCreator()
        model = dao.create_model(session)
        
        def doImport():
            import_runner = importer.ForsetiImporter(session, model)
            import_runner.run()

        self.config.runInBackground(doImport)

    def GetAccessByMembers(self, request, context):
        raise NotImplementedError()

    def GetPermissionsByRoles(self, request, context):
        raise NotImplementedError()

if __name__ == "__main__":
    class DummyConfig:
        def runInBackground(self, function):
            function()
    e = Explainer(config=DummyConfig())
    e.CreateModel("FORSETI")