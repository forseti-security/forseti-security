from google.cloud.security.iam import dao
from importer import importer

class Explainer():
    def __init__(self, config):
        self.config = config

    def GetAccessByResources(self, model_name, resource_name, permission_names, expand_groups):
        model_manager = self.config.model_manager
        session_creator, data_access = model_manager.get(model_name)
        session = session_creator()
        members = dao.explainHasAccessToResource(session,
                                                 data_access,
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
            importer_cls = importer.by_source(source)
            import_runner = importer_cls(session, model_manager.model(model_name), data_access)
            import_runner.run()

        self.config.runInBackground(doImport)
        return model_name

    def GetAccessByMembers(self, request, context):
        raise NotImplementedError()

    def GetPermissionsByRoles(self, request, context):
        raise NotImplementedError()
    
    def ListModel(self):
        model_manager = self.config.model_manager
        return model_manager.models()
    
    def DeleteModel(self, model_name):
        model_manager = self.config.model_manager
        model_manager.delete(model_name)

if __name__ == "__main__":
    class DummyConfig:
        def __init__(self):
            engine = dao.create_engine('sqlite:////tmp/test.db')
            self.model_manager = dao.ModelManager(engine)
    
        def runInBackground(self, function):
            function()

    e = Explainer(config=DummyConfig())
    e.CreateModel("TEST")