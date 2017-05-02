import dao
from importer import importer

class Explainer():
    def __init__(self, config):
        self.config = config

    def GetAccessByResources(self, resource_name, permission_names, expand_groups):
        session = self.config.getSession()
        members = dao.explainHasAccessToResource(session,
                                                 resource_name,
                                                 permission_names,
                                                 expand_groups)
        return members

    def CreateModel(self, source):
        model_manager = self.config.model_manager
        model_name = model_manager.create()
        session_creator, data_access = model_manager.get(model_name)
        session = session_creator()

        def doImport():
            import_runner = importer.ForsetiImporter(session, model_manager.model(model_name), data_access)
            import_runner.run()

        self.config.runInBackground(doImport)
        return model_name

    def GetAccessByMembers(self, request, context):
        raise NotImplementedError()

    def GetPermissionsByRoles(self, request, context):
        raise NotImplementedError()

if __name__ == "__main__":
    class DummyConfig:
        def __init__(self):
            engine = dao.create_engine('sqlite:////tmp/test.db')
            self.model_manager = dao.ModelManager(engine)
    
        def runInBackground(self, function):
            function()

    e = Explainer(config=DummyConfig())
    e.CreateModel("FORSETI")