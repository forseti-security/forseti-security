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

""" Forseti Database Objects. """

from sqlalchemy import create_engine
from sqlalchemy import Column
from sqlalchemy import String
from sqlalchemy import Text
from sqlalchemy import BigInteger
from sqlalchemy import Date
from sqlalchemy import desc

from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.sql.elements import literal_column


# TODO: The next editor must remove this disable and correct issues.
# pylint: disable=missing-type-doc,missing-return-type-doc,missing-return-doc
# pylint: disable=missing-param-doc,missing-yield-doc,missing-yield-type-doc


BASE = declarative_base()
TABLE_CACHE = {}
PER_YIELD = 1024

# pylint: disable=too-many-locals
class SnapshotState(object):
    """Possible states for Forseti snapshots."""

    SUCCESS = "SUCCESS"
    RUNNING = "RUNNING"
    FAILURE = "FAILURE"
    PARTIAL_SUCCESS = "PARTIAL_SUCCESS"
    TIMEOUT = "TIMEOUT"


class Snapshot(BASE):
    """Represents a Forseti snapshot row."""

    __tablename__ = 'snapshot_cycles'

    id = Column(BigInteger(), primary_key=True)
    start_time = Column(Date)
    complete_time = Column(Date)
    status = Column(String)
    schema_version = Column(String(255))
    cycle_timestamp = Column(String(255))

    def __repr__(self):
        return """<Snapshot(id='{}', version='{}', timestamp='{}')>""".format(
            self.id, self.schema_version, self.cycle_timestamp)


def create_table_names(timestamp, schema_version):
    """Forseti tables are namespaced via snapshot timestamp.
       This function generates the appropriate classes to
       abstract the access to a single snapshot."""

    schema_number = float(schema_version)

    if timestamp in TABLE_CACHE:
        return TABLE_CACHE[timestamp]

    class Project(BASE):
        """Represtents a GCP project row under the organization."""

        __tablename__ = 'projects_%s' % timestamp

        id = Column(BigInteger(), primary_key=True)
        project_number = Column(BigInteger())
        project_id = Column(String(255))
        project_name = Column(String(255))
        lifecycle_state = Column(String(255))
        parent_type = Column(String(255))
        parent_id = Column(String(255))
        raw_project = Column(Text())
        create_time = Column(Date)

        def __repr__(self):
            """String representation."""

            return """<Project(id='{}', project_name='{}')>""".format(
                self.id, self.project_name)

    class ProjectPolicy(BASE):
        """Represents a GCP project policy row under the organization."""

        __tablename__ = 'raw_project_iam_policies_%s' % timestamp

        id = Column(BigInteger(), primary_key=True)
        project_number = Column(BigInteger())
        iam_policy = Column(Text)

        def __repr__(self):
            """String representation."""

            return """<Policy(id='{}', type='{}', name='{}'>""".format(
                self.id, 'project', self.project_number)

        def get_resource_reference(self):
            """Return a reference to the resource in the form (type, id)."""

            return 'project', self.project_number

        def get_policy(self):
            """Return the corresponding IAM policy."""

            return self.iam_policy

    class OrganizationPolicy(BASE):
        """Represents a GCP organization policy row."""

        __tablename__ = 'raw_org_iam_policies_%s' % timestamp

        id = Column(BigInteger(), primary_key=True)
        org_id = Column(BigInteger())
        iam_policy = Column(Text)

        def __repr__(self):
            """String representation."""

            return """<Policy(id='{}', type='{}', name='{}'>""".format(
                self.id, "organization", self.org_id)

        def get_resource_reference(self):
            """Return a reference to the resource in the form (type, id)"""

            return 'organization', self.org_id

        def get_policy(self):
            """Return the corresponding IAM policy."""

            return self.iam_policy

    class Bucket(BASE):
        """Represents a GCS bucket item."""

        __tablename__ = 'buckets_%s' % timestamp

        id = Column(BigInteger(), primary_key=True)
        project_number = Column(BigInteger())
        bucket_id = Column(String(255))
        bucket_name = Column(String(255))
        bucket_kind = Column(String(255))
        bucket_storage_class = Column(String(255))
        bucket_location = Column(String(255))
        bucket_create_time = Column(Date)
        bucket_update_time = Column(Date)
        bucket_selflink = Column(String(255))
        bucket_lifecycle_raw = Column(Text)
        raw_bucket = Column(Text)

        def __repr__(self):
            """String representation."""

            return """<Bucket(id='{}', name='{}', location='{}')>""".format(
                self.bucket_id, self.bucket_name, self.bucket_location)

    class Organization(BASE):
        """Represents a GCP organization."""

        __tablename__ = 'organizations_%s' % timestamp

        org_id = Column(BigInteger(), primary_key=True)
        name = Column(String(255))
        display_name = Column(String(255))
        lifecycle_state = Column(String(255))
        raw_org = Column(Text)
        creation_time = Column(Date)

        def __repr__(self):
            """String representation."""

            fmt_s = "<Organization(id='{}', name='{}', display_name='{}')>"
            return fmt_s.format(
                self.org_id,
                self.name,
                self.display_name)

    class GroupMembers(BASE):
        """Represents Gsuite group membership."""

        __tablename__ = 'group_members_%s' % timestamp

        id = Column(BigInteger(), primary_key=True)
        group_id = Column(String(32))
        member_role = Column(String(128))
        member_type = Column(String(128))
        member_status = Column(String(128))
        member_id = Column(String(128))
        member_email = Column(String(128))
        raw_member = Column(Text())

        def __repr__(self):
            """String representation."""

            fmt_s = "<GroupMember(gid='{}', role='{}', email='{}')>"
            return fmt_s.format(
                self.group_id,
                self.member_role,
                self.member_email,
                self.member_status)

    class Groups(BASE):
        """Represents a Gsuite group."""

        __tablename__ = 'groups_%s' % timestamp

        id = Column(BigInteger(), primary_key=True)
        group_id = Column(String(127))
        group_email = Column(String(127))
        group_kind = Column(String(127))
        direct_member_count = Column(BigInteger())
        raw_group = Column(Text())

        def __repr__(self):
            """String representation."""

            fmt_s = "<Group(gid='{}', email='{}', kind='{}', members='{}')>"
            return fmt_s.format(
                self.group_id,
                self.group_email,
                self.group_kind,
                self.direct_member_count)

    class Folders(BASE):
        """Represents a folder."""

        __tablename__ = 'folders_%s' % timestamp

        folder_id = Column(BigInteger(), primary_key=True)
        name = Column(String(255))
        display_name = Column(String(255))
        lifecycle_state = Column(String(255))
        parent_type = Column(String(255))
        parent_id = Column(Text())
        raw_folder = Column(Text())

        def __repr__(self):
            """String representation."""

            fmt_s = "<Folder(fid='{}', name='{}', display_name='{}')>"
            return fmt_s.format(
                self.folder_id,
                self.name,
                self.display_name)

    if schema_number >= 2.0:
        class FolderPolicy(BASE):
            """Represents a GCP folder policy row under the organization."""

            __tablename__ = 'raw_folder_iam_policies_%s' % timestamp

            id = Column(BigInteger(), primary_key=True)
            folder_id = Column(BigInteger())
            iam_policy = Column(Text)

            def __repr__(self):
                """String representation."""

                return """<Policy(id='{}', type='{}', name='{}'>""".format(
                    self.id, 'folder', self.folder_id)

            def get_resource_reference(self):
                """Return a reference to the resource in the form (type, id).
                """

                return 'folder', self.folder_id

            def get_policy(self):
                """Return the corresponding IAM policy."""

                return self.iam_policy

    class CloudSqlInstances(BASE):
        """Represents a Cloud SQL instance."""

        __tablename__ = 'cloudsql_instances_%s' % timestamp

        id = Column(BigInteger(), primary_key=True)
        project_number = Column(BigInteger())
        name = Column(String(255))
        raw_cloudsql_instance = Column(Text())

        def __repr__(self):
            """String representation."""

            fmt_s = "<CloudSQL(id='{}', name='{}'>"
            return fmt_s.format(
                self.id,
                self.name)

    class Instances(BASE):
        """Represents a Cloud GCE instance."""

        __tablename__ = 'instances_%s' % timestamp

        id = Column(BigInteger(), primary_key=True)
        project_id = Column(String(255))
        name = Column(String(255))
        service_accounts = Column(Text())
        raw_instance = Column(Text())

        def __repr__(self):
            """String representation."""

            fmt_s = "<Instance(id='{}', name='{}'>"
            return fmt_s.format(
                self.id,
                self.name)

    class InstanceGroups(BASE):
        """Represents a Cloud GCE instance group."""

        __tablename__ = 'instance_groups_%s' % timestamp

        id = Column(BigInteger(), primary_key=True)
        project_id = Column(String(255))
        name = Column(String(255))
        raw_instance_group = Column(Text())

        def __repr__(self):
            """String representation."""

            fmt_s = "<Instance Group(id='{}', name='{}'>"
            return fmt_s.format(
                self.id,
                self.name)

    class BigqueryDatasets(BASE):
        """Represents a Cloud Bigquery dataset."""

        __tablename__ = 'bigquery_datasets_%s' % timestamp

        id = Column(BigInteger(), primary_key=True)
        project_id = Column(String(255))
        dataset_id = Column(String(255))
        raw_access_map = Column(Text())

        def __repr__(self):
            """String representation."""

            fmt_s = "<Bigquery Dataset(id='{}', name='{}'>"
            return fmt_s.format(
                self.id,
                self.dataset_id)

    class BackendServices(BASE):
        """Represents a Cloud Backend Service."""

        __tablename__ = 'backend_services_%s' % timestamp

        id = Column(BigInteger(), primary_key=True)
        project_id = Column(String(255))
        name = Column(String(255))
        raw_backend_service = Column(Text())

        def __repr__(self):
            """String representation."""

            fmt_s = "<Bigquery Dataset(id='{}', name='{}'>"
            return fmt_s.format(
                self.id,
                self.name)

    supported_policies = [OrganizationPolicy, ProjectPolicy]
    if schema_number >= 2.0:
        supported_policies.append(FolderPolicy)

    result = (Organization,
              Folders,
              [('projects', Project),
               ('buckets', Bucket),
               ('cloudsqlinstances', CloudSqlInstances),
               ('instances', Instances),
               ('instancegroups', InstanceGroups),
               ('bigquerydatasets', BigqueryDatasets),
               ('backendservices', BackendServices)],
              supported_policies,
              [GroupMembers, Groups])
    TABLE_CACHE[timestamp] = result
    return result


class Importer(object):
    """Forseti data importer to iterate the inventory and policies."""

    SUPPORTED_SCHEMAS = ['1.0', '2.0']

    def __init__(self, db_connect_string):
        engine = create_engine(db_connect_string, pool_recycle=3600)
        BASE.metadata.create_all(engine)
        session = sessionmaker(bind=engine)
        self.session = session()
        self.engine = engine

    def _table_exists_or_raise(self, table, context_msg=None):
        """Raises exception if table does not exists.
            Args:
                table (object): Table to check for existence
                context_msg (str): Additional information
            Raises:
                Exception: Indicate that the table does not exist
        """

        table_name = table.__tablename__
        if not self.engine.has_table(table_name):
            msg = 'Table not found: {}'.format(table_name)
            if context_msg:
                msg = '{}, hint: {}'.format(msg, context_msg)
            raise Exception(msg)

    def _get_latest_snapshot(self):
        """Find the latest snapshot from the database.
            Returns:
                object: Forseti snapshot description table.
        """

        return (
            self.session.query(Snapshot)
            .filter(Snapshot.status == SnapshotState.SUCCESS)
            .filter(Snapshot.schema_version.in_(self.SUPPORTED_SCHEMAS))
            .order_by(Snapshot.start_time.desc())
            .first())

    def __iter__(self):
        """Main interface to get the data, returns assets and then policies."""

        snapshot = self._get_latest_snapshot()

        organization, folders, tables, policies, group_membership = \
            create_table_names(snapshot.cycle_timestamp,
                               snapshot.schema_version)

        # Organizations
        self._table_exists_or_raise(organization)
        forseti_org = self.session.query(organization).one()
        yield "organizations", forseti_org

        # Folders
        self._table_exists_or_raise(folders)
        folder_set = (
            self.session.query(folders)
            .filter(folders.parent_type == 'organization')
            .all())

        while folder_set:
            for folder in folder_set:
                yield 'folders', folder

            folder_set = (
                self.session.query(folders)
                .filter(folders.parent_type == 'folder')
                .filter(folders.parent_id.in_(
                    [f.folder_id for f in folder_set]))
                .all()
                )

        for res_type, table in tables:
            for item in self.session.query(table).yield_per(PER_YIELD):
                yield res_type, item

        # Groups and membership
        membership, groups = group_membership
        hint = 'Did you enable Forseti group collection?'
        self._table_exists_or_raise(membership, hint)
        self._table_exists_or_raise(groups, hint)
        query_groups = (
            self.session.query(groups)
            .with_entities(literal_column("'GROUP'"), groups.group_email))
        principals = query_groups.distinct()
        for kind, email in principals.yield_per(PER_YIELD):
            yield kind.lower(), email

        query = (
            self.session.query(membership, groups)
            .filter(membership.group_id == groups.group_id)
            .order_by(desc(membership.member_email))
            .distinct())

        cur_member = None
        member_groups = []
        for member, group in query.yield_per(PER_YIELD):
            if cur_member and cur_member.member_email != member.member_email:
                if cur_member:
                    yield 'membership', (cur_member, member_groups)
                    cur_member = None
                    member_groups = []

            cur_member = member
            member_groups.append(group)

        for policy_table in policies:
            self._table_exists_or_raise(policy_table)
            for policy in self.session.query(policy_table).all():
                yield 'policy', policy
