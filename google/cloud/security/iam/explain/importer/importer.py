import forseti
from google.cloud.security.iam.explain import dao

class ForsetiImporter:
    def __init__(self, session, model):
        self.session = session
        self.model = model
        self.forseti_importer = forseti.Importer()

    def _convert_organization(self, forseti_org):
        return dao.Resource(name=forseti_org.org_id, type='organization')

    def _convert_project(self, forseti_project):
        return dao.Resource(name=forseti_project.project_number, type='project')

    def _convert_policy(self, forseti_policy):
        pass

    def run(self):
        self.model.set_inprogress(self.session)
        self.model.kick_watchdog(self.session)

        for res_type, obj in self.forseti_importer:
            if res_type == "organizations":
                self.session.add(self._convert_organization(obj))
            elif res_type == "projects":
                self.session.add(self._convert_project(obj))
            elif res_type == "buckets":
                print obj
            elif res_type == None:
                print obj
            else:
                raise NotImplementedError(res_type)
            self.model.kick_watchdog(self.session)

        self.model.set_done(self.session)
        self.session.commit()