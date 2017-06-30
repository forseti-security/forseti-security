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

from collections import defaultdict
import csv
import json
from StringIO import StringIO
from time import time
import traceback

from google.cloud.security.common.data_access import forseti
from google.cloud.security.iam.explain.importer import roles as roledef


class ResourceCache(dict):
    """Resource cache."""
    pass


class MemberCache(dict):
    """Member cache."""
    pass


class RoleCache(defaultdict):
    """Role cache."""

    def __init__(self):
        super(RoleCache, self).__init__(set)


class Member(object):
    """Member object."""

    def __init__(self, member_name):
        """Construct a member object.

        Args:
            member_name (str): name of the member in 'type/name' format.
        """
        self.type, self.name = member_name.split(':', 1)

    def get_type(self):
        """Returns the member type.

        Returns:
            str: type portion of the member.
        """

        return self.type

    def get_name(self):
        """Returns the member name.

        Returns:
            str: name portion of the member.
        """

        return self.name


class Binding(dict):
    """Binding object."""

    def get_role(self):
        """Returns the role from the binding.

        Returns:
            str: role of the binding
        """

        return self['role']

    def iter_members(self):
        """Iterate over members in the binding.
        Yields:
            Member: each member which is part of the binding.
        """

        members = self['members']
        i = 0
        while i < len(members):
            yield Member(members[i])
            i += 1


class Policy(dict):
    """Policy object."""

    def __init__(self, policy):
        """Create a Policy object from a json policy.

        Args:
            policy (object): object supporting get_policy to return json
                             formatted policy binding.
        """
        super(Policy, self).__init__(json.loads(policy.get_policy()))

    def iter_bindings(self):
        """Iterate over the policy bindings.

        Yields:
            Binding: to iterate over policy bindings.
        """

        bindings = self['bindings']
        i = 0
        while i < len(bindings):
            yield Binding(bindings[i])
            i += 1


class EmptyImporter(object):
    """Imports an empty model."""

    def __init__(self, session, model, dao, _):
        """Create an EmptyImporter which creates an empty stub model.

        Args:
            session (object): Database session.
            model (str): Model name to create.
            dao (object): Data Access Object from dao.py.
            _ (object): Unused.
        """
        self.session = session
        self.model = model
        self.dao = dao

    def run(self):
        """Runs the import."""

        self.session.commit()


class TestImporter(object):
    """Importer for testing purposes. Imports a test scenario."""

    def __init__(self, session, model, dao, _):
        """Create a TestImporter which creates a constant defined model.

        Args:
            session (object): Database session.
            model (str): Model name to create.
            dao (object): Data Access Object from dao.py.
            _ (object): Unused.
        """
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


def load_roles():
    """Load curated roles.

    Returns:
        defaultdict(set): Map from role name to set of containing permissions.
    """
    curated_roles = defaultdict(set)

    csv_content = roledef.CURATED_ROLES_CSV
    roles = csv.reader(csv_content.splitlines(),
                       delimiter=',',
                       quotechar='"')
    for entry in roles:
        role = entry[0]
        permission = entry[1]
        curated_roles[role].add(permission)
    return curated_roles


class ForsetiImporter(object):
    """Imports data from Forseti."""

    def __init__(self, session, model, dao, service_config):
        """Create a ForsetiImporter which creates a model from the Forseti DB.

        Args:
            session (object): Database session.
            model (str): Model name to create.
            dao (object): Data Access Object from dao.py.
            service_config (ServiceConfig): Service configurator.
        """
        self.session = session
        self.model = model
        self.forseti_importer = forseti.Importer(
            service_config.forseti_connect_string)
        self.resource_cache = ResourceCache()
        self.role_cache = RoleCache()
        self.dao = dao
        self.curated_roles = load_roles()

    def _convert_organization(self, forseti_org):
        """Creates a db object from a Forseti organization.

        Args:
            forseti_org (object): Forseti DB object for an organization.

        Returns:
            object: dao Resource() table object.
        """

        org_name = 'organization/{}'.format(forseti_org.org_id)
        org = self.dao.TBL_RESOURCE(
            full_name=org_name,
            type_name=org_name,
            name=forseti_org.org_id,
            type='organization',
            parent=None)
        self.resource_cache['organization'] = (org, org_name)
        self.resource_cache[org_name] = (org, org_name)
        return org

    def _convert_folder(self, forseti_folder):
        """Creates a db object from a Forseti folder.

        Args:
            forseti_folder (object): Forseti DB object for a folder.

        Returns:
            object: dao Resource() table object.
        """

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
            type_name=folder_type_name,
            name=forseti_folder.folder_id,
            type='folder',
            parent=obj,
            display_name=forseti_folder.display_name,
            )

        self.resource_cache[folder.type_name] = folder, full_folder_name
        return self.session.merge(folder)

    def _convert_project(self, forseti_project):
        """Creates a db object from a Forseti project.

        Args:
            forseti_project (object): Forseti DB object for a project.

        Returns:
            object: dao Resource() table object.
        """

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
                type_name=project_name,
                name=forseti_project.project_number,
                type='project',
                display_name=forseti_project.project_name,
                parent=obj))
        self.resource_cache[project.type_name] = (project, full_project_name)
        return project

    def _convert_bucket(self, forseti_bucket):
        """Creates a db object from a Forseti bucket.

        Args:
            forseti_bucket (object): Forseti DB object for a bucket.

        Returns:
            object: dao Resource() table object.
        """

        bucket_name = 'bucket/{}'.format(forseti_bucket.bucket_id)
        project_name = 'project/{}'.format(forseti_bucket.project_number)
        parent, full_parent_name = self.resource_cache[project_name]
        full_bucket_name = '{}/{}'.format(full_parent_name, bucket_name)
        bucket = self.session.merge(
            self.dao.TBL_RESOURCE(
                full_name=full_bucket_name,
                type_name=bucket_name,
                name=forseti_bucket.bucket_id,
                type='bucket',
                parent=parent))
        return bucket

    def _convert_cloudsqlinstance(self, forseti_cloudsqlinstance):
        """Creates a db sql instance from a Forseti sql instance.

        Args:
            forseti_cloudsqlinstance (object): Forseti DB object
                                               for a sql instance.

        Returns:
            object: dao Resource() table object.
        """

        sqlinst_name = 'cloudsqlinstance/{}'.format(
            forseti_cloudsqlinstance.name)
        project_name = 'project/{}'.format(
            forseti_cloudsqlinstance.project_number)
        parent, full_parent_name = self.resource_cache[project_name]
        full_sqlinst_name = '{}/{}'.format(full_parent_name, sqlinst_name)
        sqlinst = self.session.merge(
            self.dao.TBL_RESOURCE(
                full_name=full_sqlinst_name,
                type_name=sqlinst_name,
                name=forseti_cloudsqlinstance.name,
                type='cloudsqlinstance',
                parent=parent))
        return sqlinst

    def _convert_policy(self, forseti_policy):
        """Creates a db object from a Forseti policy.

        Args:
            forseti_policy (object): Forseti DB object for a policy.
        """

        res_type, res_id = forseti_policy.get_resource_reference()
        policy = Policy(forseti_policy)
        for binding in policy.iter_bindings():
            members = []
            for member in binding.iter_members():
                members.append(self.session.merge(
                    self.dao.TBL_MEMBER(
                        name='{}/{}'.format(member.get_type(),
                                            member.get_name()),
                        member_name=member.get_name(),
                        type=member.get_type())))

            try:
                role = self.session.query(self.dao.TBL_ROLE).filter(
                    self.dao.TBL_ROLE.name == binding.get_role()).one()
            except Exception:  # pylint: disable=broad-except
                permissions = (
                    [self.session.merge(self.dao.TBL_PERMISSION(name=p))
                     for p in self._get_permissions_for_role(
                         binding.get_role())])
                role = self.dao.TBL_ROLE(name=binding.get_role(),
                                         permissions=permissions)
                for permission in permissions:
                    self.session.add(permission)
                self.session.add(role)

            res_type_name = '{}/{}'.format(res_type, res_id)
            resource = (
                self.session.query(self.dao.TBL_RESOURCE)
                .filter(self.dao.TBL_RESOURCE.type_name == res_type_name)
                .one())
            self.session.add(
                self.dao.TBL_BINDING(resource=resource,
                                     role=role,
                                     members=members))

    def _convert_membership(self, forseti_membership):
        """Creates a db membership from a Forseti membership.

        Args:
            forseti_membership (object): Forseti DB object for a membership.

        Returns:
            object: dao Membership() table object.
        """

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
        """Creates a db group from a Forseti group.

        Args:
            forseti_group (object): Forseti DB object for a group.

        Returns:
            object: dao Member() table object.
        """

        return self.session.merge(
            self.dao.TBL_MEMBER(name='group/{}'.format(forseti_group),
                                type='group',
                                member_name=forseti_group))

    def _get_permissions_for_role(self, rolename):
        """Returns permissions defined for that role name.
        Args:
            rolename (str): role name to get permissiosn for.
        Returns:
            set: Set of permissions containing the role.
        """

        return self.curated_roles[rolename]

    def run(self):
        """Runs the import.

        Raises:
            NotImplementedError: If the importer encounters an unknown
                                 inventory type.
        """

        try:
            self.session.add(self.session.merge(self.model))
            self.model.set_inprogress(self.session)
            self.model.kick_watchdog(self.session)

            actions = {
                'organizations': self._convert_organization,
                'folders': self._convert_folder,
                'projects': self._convert_project,
                'buckets': self._convert_bucket,
                'cloudsqlinstances': self._convert_cloudsqlinstance,
                'group': self._convert_group,
                'membership': self._convert_membership,
                }

            item_counter = 0
            last_watchdog_kick = time()
            for res_type, obj in self.forseti_importer:
                item_counter += 1
                if res_type in actions:
                    self.session.add(actions[res_type](obj))
                elif res_type == 'policy':
                    self._convert_policy(obj)
                elif res_type == 'customer':
                    # TODO: investigate how we
                    # don't see this in the first place
                    pass
                else:
                    raise NotImplementedError(res_type)

                # kick watchdog about every ten seconds
                if time() - last_watchdog_kick > 10.0:
                    self.model.kick_watchdog(self.session)
                    last_watchdog_kick = time()

        except Exception:  # pylint: disable=broad-except
            buf = StringIO()
            traceback.print_exc(file=buf)
            buf.seek(0)
            message = buf.read()
            self.model.set_error(self.session, message)
        else:
            self.model.set_done(self.session, item_counter)
            self.session.commit()


def by_source(source):
    """Helper to resolve client provided import sources.

    Args:
        source (str): Source to import from.

    Returns:
        Importer: Chosen by source.
    """

    return {
        'TEST': TestImporter,
        'FORSETI': ForsetiImporter,
        'EMPTY': EmptyImporter,
    }[source.upper()]
