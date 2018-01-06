# Copyright 2017 The Forseti Security Authors. All rights reserved.
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

"""Auditor storage implementation."""

import enum
import hashlib

from datetime import datetime

from sqlalchemy import Column
from sqlalchemy import DateTime
from sqlalchemy import Enum
from sqlalchemy import ForeignKey
from sqlalchemy import ForeignKeyConstraint
from sqlalchemy import Integer
from sqlalchemy import JSON
from sqlalchemy import Table
from sqlalchemy import Text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship

# TODO: Remove this when time allows
# pylint: disable=missing-type-doc,missing-return-type-doc,missing-return-doc
# pylint: disable=missing-param-doc,invalid-name


BASE = declarative_base()
CURRENT_SCHEMA = 1
PER_YIELD = 1024


class AuditStatus(enum.Enum):
    """Possible states for audit."""

    UNSPECIFIED = 0
    RUNNING = 1
    ERROR = 2
    SUCCESS = 3


AuditRuleAssoc = Table(
    'audit_rule', BASE.metadata,
    Column('audit.id', Integer, ForeignKey('audit.id')),
    Column('rule_id', Integer, ForeignKey('rule.id')))


class Audit(BASE):
    """Represents an Audit."""

    __tablename__ = 'audit'

    id = Column(Integer(), primary_key=True, autoincrement=True)
    start_time = Column(DateTime(), default=datetime.utcnow)
    end_time = Column(DateTime(), onupdate=datetime.utcnow)
    status = Column(Enum(AuditStatus))
    model = Column(JSON())
    messages = Column(Text())
    schema_version = Column(Integer())

    rules = relationship('Rule', secondary=AuditRuleAssoc)

    def __repr__(self):
        """Object string representation.

        Returns:
            str: String representation of the object.
        """

        return '<{}(id="{}", version="{}", timestamp="{}")>'.format(
            self.__class__.__name__,
            self.id,
            self.schema_version,
            self.start_time)

    @classmethod
    def create(cls, model_handle):
        """Create a new audit row.

        Args:
            model_handle (str): The model handle.

        Returns:
            object: Audit row object.
        """

        return Audit(
            status=AuditStatus.RUNNING,
            schema_version=CURRENT_SCHEMA,
            model=model_handle)

    def complete(self, status=AuditStatus.SUCCESS):
        """Mark the audit as completed with a final status.

        Args:
            status (str): Final status.
        """

        self.status = status

    def add_warning(self, session, messages):
        """Add a warning to the audit.

        Args:
            session (object): session object to work on.
            messages (str): Warning message
        """

        warning_message = '{}\n'.format(messages)
        if not self.messages:
            self.messages = warning_message
        else:
            self.messages += warning_message
        session.add(self)
        session.commit()

    def set_error(self, session, messages):
        """Indicate a broken audit.

        Args:
            session (object): session object to work on.
            messages (str): Messages to set.
        """

        self.messages = messages
        self.status = AuditStatus.ERROR
        session.add(self)
        session.commit()


class Rule(BASE):
    """Represent a Rule."""

    __tablename__ = 'rule'

    id = Column(Integer(), primary_key=True, autoincrement=True)
    rule_name = Column(Text())
    rule_hash = Column(Text())
    properties = Column(JSON())


# TODO: don't know where this should be defined --
# creating it here for now
class RuleResultStatus(enum.Enum):
    """RuleResult statuses."""

    UNSPECIFIED = 0
    ACTIVE = 1
    RESOLVED = 2
    IGNORED = 3


class RuleResult(BASE):
    """Represent a RuleResult."""

    __tablename__ = 'rule_result'
    __table_args__ = (ForeignKeyConstraint(['audit_id'], ['audit.id']),
                      ForeignKeyConstraint(['rule_id'], ['rule.id']))

    id = Column(Integer(), primary_key=True, autoincrement=True)
    audit_id = Column(Integer(), nullable=False)
    rule_id = Column(Integer(), nullable=False)
    resource_type_name = Column(Text(), nullable=False)
    result_hash = Column(Text(), nullable=False)
    current_state = Column(JSON())
    expected_state = Column(JSON())
    model_handle = Column(Text(), nullable=False)
    resource_owners = Column(JSON())
    info = Column(Text())
    status = Column(Enum(RuleResultStatus))
    create_time = Column(DateTime(), default=datetime.utcnow)
    modified_time = Column(DateTime(), onupdate=datetime.utcnow)
    recommended_actions = Column(Text())

    def calculate_hash(self):
        """Calculate the hash of this result."""
        return hashlib.sha1(
            str((self.rule_id, self.resource_type_name, self.status))
            ).hexdigest()


class DataAccess(object):
    """Access to audit for services."""

    def __init__(self, session):
        self.session = session

    def create_audit(self, model_handle):
        """Create a new audit."""

        try:
            # TODO: change this to model data, not just the handle
            audit = Audit.create(model_handle)
            self.session.add(audit)
            self.session.commit()
        except:
            self.session.rollback()
            raise
        else:
            return audit

    def delete_audit(self, audit_id):
        """Delete an audit entry by id.

        Args:
            audit_id (int): Id specifying which audit to delete.

        Raises:
            Exception: Reraises any exception.
        """

        try:
            result = self.get_audit(audit_id)
            self.session.query(Audit).filter(
                Audit.id == audit_id).delete()
            self.session.commit()
            return result
        except Exception:
            self.session.rollback()
            raise

    def list_audits(self):
        """List all Audit entries.

        Yields:
            Audit: Generates each row
        """

        for row in self.session.query(Audit).yield_per(PER_YIELD):
            self.session.expunge(row)
            yield row

    def get_audit(self, audit_id):
        """Get an audit entry by id.

        Args:
            audit_id (int): Audit id

        Returns:
            Audit: Entry corresponding the id
        """

        result = (
            self.session.query(Audit)
            .filter(Audit.id == audit_id)
            .first())
        if result:
            self.session.expunge(result)
        return result

    def create_rule_snapshot(self, audit, rules):
        """Snapshot the rules for this audit.

        Args:
            audit (object): The Audit.
            rules (list): The list of Rules to snapshot.

        Returns:
            dict: A map of rule hashes with their corresponding
                rule id in the database.
        """

        rule_hash_ids = {}

        for rule in rules:
            try:
                rule_hash = rule.calculate_hash()
                db_rule = self.lookup_rule(rule_hash)
                if not db_rule:
                    db_rule = Rule(
                        rule_name=rule.rule_name,
                        rule_hash=rule_hash,
                        properties=rule.json)
                    audit.rules.append(db_rule)
                    self.session.add(db_rule)
                    self.session.commit()

                rule_hash_ids[rule_hash] = db_rule.id
            except:
                self.session.rollback()
                raise

        return rule_hash_ids


    def lookup_rule(self, rule_hash):
        """Lookup rule by its hash."""

        result = (
            self.session.query(Rule)
            .filter(Rule.rule_hash == rule_hash)
            .first())
        if result:
            self.session.expunge(result)
        return result

    def create_result(
            self,
            audit_id,
            rule_id,
            resource_type_name,
            current_state,
            expected_state,
            model_handle,
            info=None,
            recommended_actions=None):
        """Create a RuleResult."""

        try:
            result = RuleResult(
                audit_id=audit_id,
                rule_id=rule_id,
                resource_type_name=resource_type_name,
                current_state=current_state,
                expected_state=expected_state,
                model_handle=model_handle,
                info=info,
                status=RuleResultStatus.ACTIVE,
                recommended_actions=recommended_actions
            )
            result.result_hash = result.calculate_hash()
            db_result = self.lookup_result(result)
            if not db_result:
                self.session.add(result)
                self.session.commit()
                db_result = result
        except:
            self.session.rollback()
            raise
        else:
            return db_result

    def lookup_result(self, result):
        """Lookup a RuleResult."""

        db_result = (
            self.session.query(RuleResult)
            .filter(RuleResult.result_hash == result.result_hash)
            .first())
        if db_result:
            self.session.expunge(db_result)
        return db_result


def initialize(engine):
    """Create all tables in the database if not existing.

    Args:
        engine (object): Database engine to operate on.
    """

    BASE.metadata.create_all(engine)
