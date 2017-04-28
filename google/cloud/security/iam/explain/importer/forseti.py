#!/usr/bin/env python

import sqlalchemy
from sqlalchemy import create_engine
from sqlalchemy import Column, Integer, String, Sequence, ForeignKey, Table, Text, BigInteger, Date, Enum
from sqlalchemy.orm import relationship
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm import mapper
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.dialects.mysql import json

Base = declarative_base()

class SnapshotState:
    SUCCESS = "SUCCESS"
    RUNNING = "RUNNING"
    FAILURE = "FAILURE"
    PARTIAL_SUCCESS = "PARTIAL_SUCCESS"
    TIMEOUT = "TIMEOUT"

class Snapshot(Base):
    __tablename__ = 'snapshot_cycles'

    id = Column(BigInteger(), primary_key=True)
    start_time = Column(Date)
    complete_time = Column(Date)
    status = Column(String)
    schema_version = Column(String(255))
    cycle_timestamp = Column(String(255))

    def __repr__(self):
        return "<Snapshot(id='%s', version='%s', timestamp='%s')>" % (self.id, self.schema_version, self.cycle_timestamp)
    
def createTableNames(timestamp):
    class Project(Base):
        __tablename__ = 'projects_%s'%timestamp
        
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
            return "<Project(id='%s', project_name='%s')>"%(self.id, self.project_name)
        
    class ProjectPolicy(Base):
        __tablename__ = 'raw_project_iam_policies_%s'%timestamp

        id = Column(BigInteger(), primary_key=True)
        project_number = Column(BigInteger())
        iam_policy = Column(Text)

        def __repr__(self):
            return "<Policy(id='%s', type='%s', name='%s'"%(self.id, "project", self.project_number)

    class OrganizationPolicy(Base):
        __tablename__ = 'raw_org_iam_policies_%s'%timestamp
        
        id = Column(BigInteger(), primary_key=True)
        org_id = Column(BigInteger())
        iam_policy = Column(Text)

        def __repr__(self):
            return "<Policy(id='%s', type='%s', name='%s'"%(self.id, "organization", self.org_id)

    class Bucket(Base):
        __tablename__ = 'buckets_%s'%timestamp
        
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
            return "<Bucket(id='%s', name='%s', location='%s')>"%(self.bucket_id, self.bucket_name, self.bucket_location)

    class Organization(Base):
        __tablename__ = 'organizations_%s'%timestamp
        
        org_id = Column(BigInteger(), primary_key=True)
        name = Column(String(255))
        display_name = Column(String(255))
        lifecycle_state = Column(String(255))
        raw_org = Column(Text)
        creation_time = Column(Date)
        
        def __repr__(self):
            return "<Organization(id='%s', name='%s', display_name='%s')>"%(self.org_id, self.name, self.display_name)

    return {"projects":Project,"buckets":Bucket,"organizations":Organization},[OrganizationPolicy, ProjectPolicy]

class Importer:
    def __init__(self, db_connect_string='mysql://root@127.0.0.1:3306/forseti_security'):
        engine = create_engine(db_connect_string, pool_recycle=3600)
        Base.metadata.create_all(engine)
        Session = sessionmaker(bind=engine)
        self.session = Session()
        self._get_latest_snapshot()

    def _get_latest_snapshot(self):
        self.snapshot = self.session.query(Snapshot).filter(Snapshot.status == SnapshotState.SUCCESS).order_by(Snapshot.start_time.desc()).first()

    def __iter__(self):
        tables, policies = createTableNames(self.snapshot.cycle_timestamp)
        for table in tables.itervalues():
            for item in self.session.query(table).all():
                yield item
        
        for policyTable in policies:
            for policy in self.session.query(policyTable).all():
                yield policy

if __name__ == '__main__':
    i = Importer()
    for x in i:
        print x