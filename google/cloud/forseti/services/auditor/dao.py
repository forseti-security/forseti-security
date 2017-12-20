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

""" Database access objects for Forseti Auditor."""

import json

from sqlalchemy import Column
from sqlalchemy import String, Integer, Text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

from google.cloud.forseti.services import db


# pylint: disable=no-member

def define_violation(model_name, dbengine):
    """Defines table class for violations.

    A violation table will be created on a per-model basis.

    Args:
        model_name (str): name of the current model
        dbengine (engine): sqlalchemy database engine

    Returns:
        ViolationAcccess: facade for accessing violations.
    """

    base = declarative_base()
    violations_tablename = '{}_violations'.format(model_name)

    class Violation(base):
        """Row entry for a violation."""

        __tablename__ = violations_tablename

        id = Column(Integer, primary_key=True)
        resource_type = Column(String(256), nullable=False)
        rule_name = Column(String(256))
        rule_index = Column(Integer, default=0)
        violation_type = Column(String(256), nullable=False)
        data = Column(Text)

        def __repr__(self):
            """String representation.

            Returns:
                str: string representation of the Violation row entry.
            """
            string = ("<Violation(violation_type='{}', resource_type='{}' "
                      "rule_name='{}')>")
            return string.format(
                self.violation_type, self.resource_type, self.rule_name)

    class ViolationAccess(object):
        """Facade for violations, implement APIs against violations table."""
        TBL_VIOLATIONS = Violation

        def __init__(self, dbengine):
            """Constructor for the Violation Access.

            Args:
                dbengine (engine): sqlalchemy database engine
            """
            self.engine = dbengine
            self.violationmaker = self._create_violation_session()

        def _create_violation_session(self):
            """Create a session to read from the models table.

            Returns:
                ScopedSessionmaker: A scoped session maker that will create
                    a session that is automatically released.
            """
            return db.ScopedSessionMaker(
                sessionmaker(
                    bind=self.engine,
                    expire_on_commit=False),
                auto_commit=True)

        def create(self, violations):
            """Save violations to the db table.

            Args:
                violations (list): A list of violations.
            """
            with self.violationmaker() as session:
                for violation in violations:
                    violation = self.TBL_VIOLATIONS(
                        resource_type=violation.get('resource_type'),
                        rule_name=violation.get('rule_name'),
                        rule_index=violation.get('rule_index'),
                        violation_type=violation.get('violation_type'),
                        data=json.dumps(violation.get('violation_data'))
                    )
                    session.add(violation)

        def list(self):
            """List all violations from the db table.

            Returns:
                list: List of Violation row entry objects.
            """
            with self.violationmaker() as session:
                return session.query(self.TBL_VIOLATIONS).all()


    base.metadata.create_all(dbengine)

    return ViolationAccess
