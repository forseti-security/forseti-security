import json

import forseti

class ResourceCache(dict):
    pass

class MemberCache(dict):
    pass

class Member:
    def __init__(self, member_name):
        self.type, self.name = member_name.split(':', 1)

    def getType(self):
        return self.type

    def getName(self):
        return self.name

class Binding(dict):
    def getrole(self):
        return self['role']
    
    def itermembers(self):
        members = self['members']
        i = 0
        while i < len(members):
            yield Member(members[i])
            i+=1
    
class Policy(dict):
    def __init__(self, policy):
        super(Policy, self).__init__(json.loads(policy.getPolicy()))

    def iterbindings(self):
        bindings = self['bindings']
        i = 0
        while i < len(bindings):
            yield Binding(bindings[i])
            i+=1
            
class TestImporter:
    def __init__(self, session, model, dao):
        self.session = session
        self.model = model
        self.dao = dao
        
    def run(self):
        project = self.dao.addResource(self.session, 'project')
        vm = self.dao.addResource(self.session, 'vm1', project)
        db = self.dao.addResource(self.session, 'db1', project)

        permission1 = self.dao.addPermission(self.session, 'cloudsql.table.read')
        permission2 = self.dao.addPermission(self.session, 'cloudsql.table.write')

        role1 = self.dao.addRole(self.session, 'sqlreader', [permission1])
        role2 = self.dao.addRole(self.session, 'sqlwriter', [permission1, permission2])

        group1 = self.dao.addMember(self.session, 'group1', 'group')
        group2 = self.dao.addMember(self.session, 'group2', 'group', [group1]) 

        member1 = self.dao.addMember(self.session, 'felix', 'user', [group2])
        member2 = self.dao.addMember(self.session, 'fooba', 'user', [group2])

        binding = self.dao.addBinding(self.session, vm, role1, [group1])
        binding = self.dao.addBinding(self.session, project, role2, [group2])
        self.session.commit()

class ForsetiImporter:
    def __init__(self, session, model, dao):
        self.session = session
        self.model = model
        self.forseti_importer = forseti.Importer()
        self.resource_cache = ResourceCache()
        self.dao = dao

    def _convert_organization(self, forseti_org):
        org_name = 'organization/{}'.format(forseti_org.org_id)
        org = self.dao.TBL_RESOURCE(full_name=org_name, name=org_name, type='organization', parent=None)
        self.resource_cache['organization'] = (org, org_name)
        return org

    def _convert_project(self, forseti_project):
        org, org_name = self.resource_cache['organization']
        project_name = 'project/{}'.format(forseti_project.project_number)
        full_project_name = '{}/project/{}'.format(org_name, forseti_project.project_number)
        project = self.dao.TBL_RESOURCE(full_name=full_project_name, name=project_name, type='project', parent=org)
        self.resource_cache[project_name] = (project, full_project_name)
        return project

    def _convert_bucket(self, forseti_bucket):
        bucket_name = 'bucket/{}'.format(forseti_bucket.bucket_id)
        project_name = 'project/{}'.format(forseti_bucket.project_number)
        parent, full_parent_name = self.resource_cache[project_name]
        full_bucket_name = '{}/{}'.format(full_parent_name, bucket_name)
        bucket = self.dao.TBL_RESOURCE(full_name=full_bucket_name, name=bucket_name, type='bucket', parent=parent)
        self.resource_cache[bucket_name] = (bucket, full_bucket_name)
        return bucket

    def _convert_policy(self, forseti_policy):
        res_type, res_id = forseti_policy.getResourceReference()
        policy = Policy(forseti_policy)
        for binding in policy.iterbindings():
            self.session.merge(self.dao.TBL_ROLE(name=binding.getrole()))
            for member in binding.itermembers():
                self.session.merge(self.dao.TBL_MEMBER(name=member.getName(), type=member.getType()))

    def run(self):
        self.model.set_inprogress(self.session)
        self.model.kick_watchdog(self.session)

        for res_type, obj in self.forseti_importer:
            if res_type == "organizations":
                self.session.add(self._convert_organization(obj))
            elif res_type == "projects":
                self.session.add(self._convert_project(obj))
            elif res_type == "buckets":
                self.session.add(self._convert_bucket(obj))
            elif res_type == 'policy':
                self._convert_policy(obj)
            else:
                raise NotImplementedError(res_type)
            self.model.kick_watchdog(self.session)

        self.model.set_done(self.session)
        self.session.commit()
        
def by_source(source):
    return {
        "TEST":TestImporter,
        "FORSETI":ForsetiImporter,
        }[source]