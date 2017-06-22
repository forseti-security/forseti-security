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
import traceback
from collections import defaultdict
from time import time
from StringIO import StringIO

from google.cloud.security.common.data_access import forseti


# TODO: The next editor must remove this disable and correct issues.
# pylint: disable=missing-type-doc,missing-return-type-doc,missing-return-doc
# pylint: disable=missing-param-doc,missing-yield-doc
# pylint: disable=missing-yield-type-doc,missing-raises-doc

# pylint: disable=unused-argument,too-many-branches
# pylint: disable=broad-except
# pylint: disable=bare-except


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
        self.role_cache = RoleCache()
        self.dao = dao

    def _convert_organization(self, forseti_org):
        """Creates a db object from a Forseti organization."""

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
            type_name=folder_type_name,
            name=forseti_folder.folder_id,
            type='folder',
            parent=obj,
            display_name=forseti_folder.display_name,
            )

        self.resource_cache[folder.type_name] = folder, full_folder_name
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
                type_name=project_name,
                name=forseti_project.project_number,
                type='project',
                display_name=forseti_project.project_name,
                parent=obj))
        self.resource_cache[project.type_name] = (project, full_project_name)
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
                type_name=bucket_name,
                name=forseti_bucket.bucket_id,
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
                type_name=sqlinst_name,
                name=forseti_cloudsqlinstance.name,
                type='cloudsqlinstance',
                parent=parent))
        return sqlinst

    def _convert_policy(self, forseti_policy):
        """Creates a db object from a Forseti policy."""

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

            def dummy_generate_permissions():
                """Dummy generate permissions."""
                import random
                perms = [
                    'a.b.c',
                    'd.e.f',
                    'g.h.i',
                    'j.k.l',
                    'm.n.o',
                    'foo.bar.baz',
                    ]
                return (list(set([random.choice(perms)
                                  for _ in range(int(random.random()*10))])))

            try:
                role = self.session.query(self.dao.TBL_ROLE).filter(
                    self.dao.TBL_ROLE.name == binding.get_role()).one()
            except:
                permissions = (
                    [self.session.merge(self.dao.TBL_PERMISSION(name=p))
                     for p in dummy_generate_permissions()])
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
        """Runs the import."""
        try:
            self.session.add(self.session.merge(self.model))
            self.model.set_inprogress(self.session)
            self.model.kick_watchdog(self.session)

            item_counter = 0
            last_watchdog_kick = time()
            for res_type, obj in self.forseti_importer:
                item_counter += 1
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
                    # TODO: investigate how we
                    # don't see this in the first place
                    pass
                else:
                    raise NotImplementedError(res_type)

                # kick watchdog about every ten seconds
                if time() - last_watchdog_kick > 10.0:
                    self.model.kick_watchdog(self.session)
                    last_watchdog_kick = time()

        except Exception:
            buf = StringIO()
            traceback.print_exc(file=buf)
            buf.seek(0)
            message = buf.read()
            self.model.set_error(self.session, message)
        else:
            self.model.set_done(self.session, item_counter)
            self.session.commit()


def by_source(source):
    """Helper to resolve client provided import sources."""

    return {
        'TEST': TestImporter,
        'FORSETI': ForsetiImporter,
        'EMPTY': EmptyImporter,
    }[source.upper()]
