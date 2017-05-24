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
from sqlalchemy import Column, String
from sqlalchemy import Text, BigInteger, Date
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base

BASE = declarative_base()


# pylint: disable=R0914
# pylint: disable=R0903
# pyling: disable=R0904
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


TABLE_CACHE = {}


def create_table_names(timestamp):
    """Forseti tables are namespaced via snapshot timestamp.
       This function generates the appropriate classes to
       abstract the access to a single snapshot."""

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
            return "<Organization(id='{}', name='{}', display_name='{}')>".\
                format(self.org_id, self.name, self.display_name)

    result = (Organization,
              [('projects', Project), ('buckets', Bucket)],
              [OrganizationPolicy, ProjectPolicy])
    TABLE_CACHE[timestamp] = result
    return result


class Importer(object):
    """Forseti data importer to iterate the inventory and policies."""
    DEFAULT_CONNECT_STRING = 'mysql://root@127.0.0.1:3306/forseti_security'

    def __init__(self, db_connect_string=DEFAULT_CONNECT_STRING):
        engine = create_engine(db_connect_string, pool_recycle=3600)
        BASE.metadata.create_all(engine)
        session = sessionmaker(bind=engine)
        self.session = session()
        self._get_latest_snapshot()

    def _get_latest_snapshot(self):
        """Find the latest snapshot from the database."""
        self.snapshot = self.session.query(Snapshot).\
            filter(Snapshot.status == SnapshotState.SUCCESS).\
            order_by(Snapshot.start_time.desc()).first()

    def __iter__(self):
        """Main interface to get the data, returns assets and then policies."""
        organization, tables, policies = \
            create_table_names(self.snapshot.cycle_timestamp)
        yield "organizations", self.session.query(organization).one()
        for res_type, table in tables:
            for item in self.session.query(table).all():
                yield res_type, item

        for policy_table in policies:
            for policy in self.session.query(policy_table).all():
                yield 'policy', policy
