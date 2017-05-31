# Copyright 2017 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

""" Importer implementations. """

import json

from google.cloud.security.common.data_access import forseti

# pylint: disable=unused-argument

class ResourceCache(dict):
    """Resource cache."""
    pass


class MemberCache(dict):
    """Member cache."""
    pass


class Member(object):
    """Member object."""
    def __init__(self, member_name):
        self.type, self.name = member_name.split(':', 1)

    def get_type(self):
        """Returns the member type."""
        return self.type

    def get_name(self):
        """Returns the member name."""
        return self.name


class Binding(dict):
    """Binding object."""
    def get_role(self):
        """Returns the role from the binding."""
        return self['role']

    def iter_members(self):
        """Iterate over members in the binding."""
        members = self['members']
        i = 0
        while i < len(members):
            yield Member(members[i])
            i += 1


class Policy(dict):
    """Policy object."""
    def __init__(self, policy):
        super(Policy, self).__init__(json.loads(policy.get_policy()))

    def iter_bindings(self):
        """Iterate over the policy bindings."""
        bindings = self['bindings']
        i = 0
        while i < len(bindings):
            yield Binding(bindings[i])
            i += 1


class EmptyImporter(object):
    """Imports an empty model."""
    def __init__(self, session, model, dao, service_config):
        self.session = session
        self.model = model
        self.dao = dao

    def run(self):
        """Runs the import."""
        self.session.commit()


class TestImporter(object):
    """Importer for testing purposes. Imports a test scenario."""
    def __init__(self, session, model, dao, service_config):
        self.session = session
        self.model = model
        self.dao = dao

    def run(self):
        """Runs the import."""
        project = self.dao.add_resource(self.session, 'project')
        instance = self.dao.add_resource(self.session, 'vm1', project)
        _ = self.dao.add_resource(self.session, 'db1', project)

        permission1 = self.dao.add_permission(
            self.session, 'cloudsql.table.read')
        permission2 = self.dao.add_permission(
            self.session, 'cloudsql.table.write')

        role1 = self.dao.add_role(self.session, 'sqlreader', [permission1])
        role2 = self.dao.add_role(
            self.session, 'sqlwriter', [
                permission1, permission2])

        group1 = self.dao.add_member(self.session, 'group1', 'group')
        group2 = self.dao.add_member(self.session, 'group2', 'group', [group1])

        _ = self.dao.add_member(self.session, 'felix', 'user', [group2])
        _ = self.dao.add_member(self.session, 'fooba', 'user', [group2])

        _ = self.dao.add_binding(self.session, instance, role1, [group1])
        _ = self.dao.add_binding(self.session, project, role2, [group2])
        self.session.commit()


class ForsetiImporter(object):
    """Imports data from Forseti."""
    def __init__(self, session, model, dao, service_config):
        self.session = session
        self.model = model
        self.forseti_importer = forseti.Importer(
            service_config.forseti_connect_string)
        self.resource_cache = ResourceCache()
        self.dao = dao

    def _convert_organization(self, forseti_org):
        """Creates a db object from a Forseti organization."""
        org_name = 'organization/{}'.format(forseti_org.org_id)
        org = self.dao.TBL_RESOURCE(
            full_name=org_name,
            name=org_name,
            type='organization',
            parent=None)
        self.resource_cache['organization'] = (org, org_name)
        return org

    def _convert_project(self, forseti_project):
        """Creates a db object from a Forseti project."""
        org, org_name = self.resource_cache['organization']
        project_name = 'project/{}'.format(forseti_project.project_number)
        full_project_name = '{}/project/{}'.format(
            org_name, forseti_project.project_number)
        project = self.dao.TBL_RESOURCE(
            full_name=full_project_name,
            name=project_name,
            type='project',
            parent=org)
        self.resource_cache[project_name] = (project, full_project_name)
        return project

    def _convert_bucket(self, forseti_bucket):
        """Creates a db object from a Forseti bucket."""
        bucket_name = 'bucket/{}'.format(forseti_bucket.bucket_id)
        project_name = 'project/{}'.format(forseti_bucket.project_number)
        parent, full_parent_name = self.resource_cache[project_name]
        full_bucket_name = '{}/{}'.format(full_parent_name, bucket_name)
        bucket = self.dao.TBL_RESOURCE(
            full_name=full_bucket_name,
            name=bucket_name,
            type='bucket',
            parent=parent)
        self.resource_cache[bucket_name] = (bucket, full_bucket_name)
        return bucket

    def _convert_policy(self, forseti_policy):
        """Creates a db object from a Forseti policy."""
        # res_type, res_id = forseti_policy.getResourceReference()
        policy = Policy(forseti_policy)
        for binding in policy.iter_bindings():
            self.session.merge(self.dao.TBL_ROLE(name=binding.get_role()))
            for member in binding.iter_members():
                self.session.merge(
                    self.dao.TBL_MEMBER(
                        name=member.get_name(),
                        type=member.get_type()))

    def run(self):
        """Runs the import."""
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
    """Helper to resolve client provided import sources."""
    return {
        "TEST": TestImporter,
        "FORSETI": ForsetiImporter,
        "EMPTY": EmptyImporter,
    }[source]
