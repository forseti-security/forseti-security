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
from google.cloud.security.iam.dao import create_engine
from google.cloud.security.iam.dao import ModelManager



# TODO: The next editor must remove this disable and correct issues.
# pylint: disable=missing-type-doc,missing-return-type-doc,missing-return-doc
# pylint: disable=missing-param-doc,missing-yield-doc
# pylint: disable=missing-yield-type-doc


# pylint: disable=unused-argument
# pylint: disable=no-self-use

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
        self.resource_cache[org_name] = (org, org_name)
        return org

    def _convert_folder(self, forseti_folder):
        """Creates a db object from a Forseti folder."""

        parent_type_name = '{}/{}'.format(
            forseti_folder.parent_type,
            forseti_folder.parent_id)

        obj, full_res_name = self.resource_cache[parent_type_name]

        full_folder_name = '{}/folder/{}'.format(
            full_res_name, forseti_folder.folder_id)
        folder_type_name = 'folder/{}'.format(
            forseti_folder.folder_id)
        folder = self.dao.TBL_RESOURCE(
            full_name=full_folder_name,
            name=folder_type_name,
            type='folder',
            parent=obj,
            display_name=forseti_folder.display_name,
            )

        self.resource_cache[folder.name] = folder, full_folder_name
        return self.session.merge(folder)

    def _convert_project(self, forseti_project):
        """Creates a db object from a Forseti project."""

        parent_type_name = '{}/{}'.format(
            forseti_project.parent_type,
            forseti_project.parent_id)

        obj, full_res_name = self.resource_cache[parent_type_name]
        project_name = 'project/{}'.format(forseti_project.project_number)
        full_project_name = '{}/project/{}'.format(
            full_res_name, forseti_project.project_number)
        project = self.session.merge(
            self.dao.TBL_RESOURCE(
                full_name=full_project_name,
                name=project_name,
                type='project',
                display_name=forseti_project.project_name,
                parent=obj))
        self.resource_cache[project_name] = (project, full_project_name)
        return project

    def _convert_bucket(self, forseti_bucket):
        """Creates a db object from a Forseti bucket."""

        bucket_name = 'bucket/{}'.format(forseti_bucket.bucket_id)
        project_name = 'project/{}'.format(forseti_bucket.project_number)
        parent, full_parent_name = self.resource_cache[project_name]
        full_bucket_name = '{}/{}'.format(full_parent_name, bucket_name)
        bucket = self.session.merge(
            self.dao.TBL_RESOURCE(
                full_name=full_bucket_name,
                name=bucket_name,
                type='bucket',
                parent=parent))
        return bucket

    def _convert_cloudsqlinstance(self, forseti_cloudsqlinstance):
        """Creates a db sql instance from a Forseti sql instance."""

        sqlinst_name = 'cloudsqlinstance/{}'.format(
            forseti_cloudsqlinstance.name)
        project_name = 'project/{}'.format(
            forseti_cloudsqlinstance.project_number)
        parent, full_parent_name = self.resource_cache[project_name]
        full_sqlinst_name = '{}/{}'.format(full_parent_name, sqlinst_name)
        sqlinst = self.session.merge(
            self.dao.TBL_RESOURCE(
                full_name=full_sqlinst_name,
                name=sqlinst_name,
                type='cloudsqlinstance',
                parent=parent))
        return sqlinst

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

    def _convert_membership(self, forseti_membership):
        """Creates a db membership from a Forseti membership."""
        member, groups = forseti_membership

        groups = [self.session.merge(
            self.dao.TBL_MEMBER(name='group/{}'.format(group.group_email),
                                type='group',
                                member_name=group.group_email))
                  for group in groups]

        member_type = member.member_type.lower()
        member_name = member.member_email
        return self.session.merge(self.dao.TBL_MEMBER(
            name='{}/{}'.format(member_type, member_name),
            type=member_type,
            member_name=member_name,
            parents=groups))

    def _convert_group(self, forseti_group):
        """Creates a db group from a Forseti group."""
        return self.session.merge(
            self.dao.TBL_MEMBER(name='group/{}'.format(forseti_group),
                                type='group',
                                member_name=forseti_group))

    def run(self):
        """Runs the import.

            Raises:
                NotImplementedError: If the resource type isn't found.
        """

        self.model.set_inprogress(self.session)
        self.model.kick_watchdog(self.session)

        for res_type, obj in self.forseti_importer:
            print 'type: {}, obj: {}'.format(res_type, obj)
            if res_type == 'organizations':
                self.session.add(self._convert_organization(obj))
            elif res_type == 'folders':
                self.session.add(self._convert_folder(obj))
            elif res_type == 'projects':
                self.session.add(self._convert_project(obj))
            elif res_type == 'buckets':
                self.session.add(self._convert_bucket(obj))
            elif res_type == 'cloudsqlinstances':
                self.session.add(self._convert_cloudsqlinstance(obj))
            elif res_type == 'policy':
                self._convert_policy(obj)
            elif res_type == 'group':
                self.session.add(self._convert_group(obj))
            elif res_type == 'membership':
                self.session.add(self._convert_membership(obj))
            elif res_type == 'customer':
                pass
            else:
                raise NotImplementedError(res_type)
            #self.model.kick_watchdog(self.session)

        self.model.set_done(self.session)
        self.session.commit()


def by_source(source):
    """Helper to resolve client provided import sources."""

    return {
        'TEST': TestImporter,
        'FORSETI': ForsetiImporter,
        'EMPTY': EmptyImporter,
    }[source]


class ServiceConfig(object):
    """
    ServiceConfig is a helper class to implement dependency injection
    to IAM Explain services.
    """

    def __init__(self, explain_connect_string, forseti_connect_string):
        engine = create_engine(explain_connect_string, echo=True)
        self.model_manager = ModelManager(engine)
        self.forseti_connect_string = forseti_connect_string

    def run_in_background(self, function):
        """Runs a function in a thread pool in the background."""
        return function()

def test_run():
    """Test run."""

    #explain_conn_s = 'sqlite:///:memory:'
    explain_conn_s = 'mysql://felix@127.0.0.1:3306/explain_forseti'
    forseti_conn_s = 'mysql://felix@127.0.0.1:3306/forseti_security'

    svc_config = ServiceConfig(explain_conn_s, forseti_conn_s)
    source = 'FORSETI'
    model_manager = svc_config.model_manager
    model_name = model_manager.create()
    print 'model name: {}'.format(model_name)

    scoped_session, data_access = model_manager.get(model_name)
    with scoped_session as session:

        def do_import():
            """Import runnable."""
            importer_cls = by_source(source)
            import_runner = importer_cls(
                session,
                model_manager.model(model_name),
                data_access,
                svc_config)
            import_runner.run()

        svc_config.run_in_background(do_import)
        return model_name


if __name__ == "__main__":
    test_run()
