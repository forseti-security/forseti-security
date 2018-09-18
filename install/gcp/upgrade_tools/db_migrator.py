# Copyright 2017 The Forseti Security Authors. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Forseti db migrator."""

from __future__ import print_function

import sys

# Importing migrate.changeset adds some new methods to existing SQLAlchemy
# objects but we will not be calling the library directly.
import migrate.changeset  # noqa: F401, pylint: disable=unused-import
from sqlalchemy.exc import OperationalError

import google.cloud.forseti.services.scanner.dao as scanner_dao
import google.cloud.forseti.services.inventory.storage as inventory_dao
import google.cloud.forseti.services.dao as general_dao

from google.cloud.forseti.common.util import logger


DEFAULT_DB_CONN_STR = 'mysql://root@127.0.0.1:3306/forseti_security'
LOGGER = logger.get_logger(__name__)


class ColumnAction(object):
    """Column action class."""
    DROP = 'DROP'
    CREATE = 'CREATE'


def create_column(table, column):
    """Create Column.

    Args:
        table (sqlalchemy.schema.Table): The sql alchemy table object.
        column (sqlalchemy.schema.Column): The sql alchemy column object.
    """
    LOGGER.info('Attempting to create column: %s', column.name)
    column.create(table, populate_default=True)


def drop_column(table, column):
    """Create Column.

    Args:
        table (sqlalchemy.schema.Table): The sql alchemy table object.
        column (sqlalchemy.schema.Column): The sql alchemy column object.
    """
    LOGGER.info('Attempting to drop column: %s', column.name)
    column.drop(table)


COLUMN_ACTION_MAPPING = {ColumnAction.DROP: drop_column,
                         ColumnAction.CREATE: create_column}


def migrate_schema(engine, base):
    """Create all tables in the database if not existing.

    Args:
        engine (object): Database engine to operate on.
        base (Base): Declarative base.
    """
    # Create tables if not exists.
    base.metadata.create_all(engine)
    base.metadata.bind = engine

    # Update schema changes.
    # Find all the child classes inherited from declarative base class.
    base_subclasses = _find_subclasses(base)

    # Find all the Table objects for each of the classes.
    # The format of tables is: {table_name: Table object}.
    tables = base.metadata.tables

    schema_update_actions_method = 'get_schema_update_actions'

    for subclass in base_subclasses:
        get_schema_update_actions = getattr(subclass,
                                            schema_update_actions_method,
                                            None)
        if (not callable(get_schema_update_actions) or
                subclass.__tablename__ not in tables):
            LOGGER.warn('Method: %s is not callable or Table: %s doesn\t '
                        'exist', schema_update_actions_method,
                        subclass.__tablename__)
            continue
        LOGGER.info('Updating table %s', subclass.__tablename__)
        # schema_update will require the Table object.
        table = tables.get(subclass.__tablename__)
        schema_update_mapping = get_schema_update_actions()
        for column_action, columns in schema_update_mapping.iteritems():
            column_action = column_action.upper()
            if column_action in COLUMN_ACTION_MAPPING:
                for column in columns:
                    try:
                        COLUMN_ACTION_MAPPING.get(column_action)(table,
                                                                 column)
                    except OperationalError:
                        LOGGER.info('Failed to update db schema, table=%s',
                                    subclass.__tablename__)
                    except Exception:  # pylint: disable=broad-except
                        LOGGER.exception(
                            'Unexpected error happened when attempting '
                            'to update database schema, table: %s',
                            subclass.__tablename__)
            else:
                LOGGER.warn('Columns: %s, ColumnAction %s doesn\'t '
                            'exist.', columns, column_action)


def _find_subclasses(cls):
    """Find all the subclasses of a class.

    Args:
        cls (class): The parent class.

    Returns:
        list: Subclasses of the given parent class.
    """
    results = []
    for subclass in cls.__subclasses__():
        results.append(subclass)
    return results


if __name__ == '__main__':
    # If the DB connection string is passed in, use that, otherwise
    # fall back to the default DB connection string.
    print (sys.argv)
    DB_CONN_STR = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_DB_CONN_STR

    SQL_ENGINE = general_dao.create_engine(DB_CONN_STR,
                                           pool_recycle=3600)

    DECLARITIVE_BASES = [scanner_dao.BASE, inventory_dao.BASE]

    for declaritive_base in DECLARITIVE_BASES:
        migrate_schema(SQL_ENGINE, declaritive_base)
