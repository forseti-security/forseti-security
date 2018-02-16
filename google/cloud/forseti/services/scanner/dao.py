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

""" Database access objects for Forseti Scanner. """

from collections import defaultdict
import json

from sqlalchemy import Column
from sqlalchemy import String, Integer, Text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import inspect
from sqlalchemy.orm import sessionmaker

from google.cloud.forseti.common.util import logger
from google.cloud.forseti.services import db


LOGGER = logger.get_logger(__name__)


# pylint: disable=no-member

def define_violation(dbengine):
    """Defines table class for violations.

    A violation table will be created on a per-model basis.

    Args:
        dbengine (engine): sqlalchemy database engine

    Returns:
        ViolationAcccess: facade for accessing violations.
    """
    # TODO: Determine if dbengine is really needed as a method arg here.
    base = declarative_base()
    violations_tablename = 'violations'

    class Violation(base):
        """Row entry for a violation."""

        __tablename__ = violations_tablename

        id = Column(Integer, primary_key=True)
        inventory_index_id = Column(String(256))
        resource_id = Column(String(256), nullable=False)
        resource_type = Column(String(256), nullable=False)
        full_name = Column(String(1024))
        rule_name = Column(String(256))
        rule_index = Column(Integer, default=0)
        violation_type = Column(String(256), nullable=False)
        violation_data = Column(Text)
        inventory_data = Column(Text)

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

        def create(self, violations, inventory_index_id):
            """Save violations to the db table.

            Args:
                violations (list): A list of violations.
                inventory_index_id (str): Id of the inventory index.
            """
            with self.violationmaker() as session:
                for violation in violations:
                    violation = self.TBL_VIOLATIONS(
                        inventory_index_id=inventory_index_id,
                        resource_id=violation.get('resource_id'),
                        resource_type=violation.get('resource_type'),
                        full_name=violation.get('full_name'),
                        rule_name=violation.get('rule_name'),
                        rule_index=violation.get('rule_index'),
                        violation_type=violation.get('violation_type'),
                        violation_data=json.dumps(
                            violation.get('violation_data')),
                        inventory_data=violation.get('inventory_data')
                    )
                    session.add(violation)

        def list(self, inventory_index_id=None):
            """List all violations from the db table.

            Args:
                inventory_index_id (str): Id of the inventory index.

            Returns:
                list: List of Violation row entry objects.
            """
            with self.violationmaker() as session:
                if inventory_index_id:
                    return (
                        session.query(self.TBL_VIOLATIONS)
                        .filter(
                            self.TBL_VIOLATIONS.inventory_index_id ==
                            inventory_index_id)
                        .all())
                return (
                    session.query(self.TBL_VIOLATIONS)
                    .all())

    base.metadata.create_all(dbengine)

    return ViolationAccess

# pylint: disable=invalid-name
def convert_sqlalchemy_object_to_dict(sqlalchemy_obj):
    """Convert a sqlalchemy row/record object to a dictionary.

    Args:
        sqlalchemy_obj (sqlalchemy_object): A sqlalchemy row/record object

    Returns:
        dict: A dict of sqlalchemy object's attributes.
    """

    return {c.key: getattr(sqlalchemy_obj, c.key)
            for c in inspect(sqlalchemy_obj).mapper.column_attrs}
