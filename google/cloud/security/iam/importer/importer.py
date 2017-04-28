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

    return {"project":Project}

engine = create_engine('mysql://root@127.0.0.1:3306/forseti_security', pool_recycle=3600, echo=True)
Base.metadata.create_all(engine)
Session = sessionmaker(bind=engine)
session = Session()


snapshot = session.query(Snapshot).filter(Snapshot.status == SnapshotState.SUCCESS).order_by(Snapshot.start_time.desc()).first()
tables = createTableNames(snapshot.cycle_timestamp)

for key, table in tables.iteritems():
    for item in session.query(table).all():
        print item

import code
code.interact(local=locals())
