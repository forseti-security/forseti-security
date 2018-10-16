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
    ALTER = 'ALTER'


def create_column(table, column):
    """Create Column.

    Args:
        table (sqlalchemy.schema.Table): The sql alchemy table object.
        column (sqlalchemy.schema.Column): The sql alchemy column object.
    """
    LOGGER.info('Attempting to create column: %s', column.name)
    column.create(table, populate_default=True)


def alter_column(table, column):
    """Alter Column.

    Args:
        table (sqlalchemy.schema.Table): The sql alchemy table object.
        old_column (sqlalchemy.schema.Column): The sql alchemy column object,
            this is the column to be modified.
        new_column (sqlalchemy.schema.Column): The sql alchemy column object,
            this is the column to update to.
    """
    LOGGER.info('Attempting to alter column: %s', column.name)
    column.alter(table, table.metadata.bind)


def drop_column(table, column):
    """Create Column.

    Args:
        table (sqlalchemy.schema.Table): The sql alchemy table object.
        column (sqlalchemy.schema.Column): The sql alchemy column object.
    """
    LOGGER.info('Attempting to drop column: %s', column.name)
    column.drop(table)


COLUMN_ACTION_MAPPING = {ColumnAction.DROP: drop_column,
                         ColumnAction.CREATE: create_column,
                         ColumnAction.ALTER: alter_column}


def migrate_schema(base, base_subclasses):
    """Create all tables in the database if not existing.

    Args:
        base (Base): Declarative base.
        base_subclasses (list): A list of subclasses.
    """

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
        schema_update_actions = get_schema_update_actions()
        for column_action, columns in schema_update_actions.iteritems():
            if column_action in [ColumnAction.CREATE, ColumnAction.DROP]:
                _create_or_drop_columns(column_action, columns, table)
            elif column_action in [ColumnAction.ALTER]:
                _alter_columns(column_action, columns, table)
            else:
                LOGGER.warn('Unknown column action: %s', column_action)


def _alter_columns(column_action, columns, table):
    """Alter columns.

    Args:
        column_action (str): Column Action.
        columns (dict): A dictionary of old_column: new_column.
        table (sqlalchemy.schema.Table): The sql alchemy table object.
    """
    column_action = column_action.upper()
    for old_column, new_column in columns.iteritems():
        try:
            COLUMN_ACTION_MAPPING.get(column_action)(table,
                                                     old_column,
                                                     new_column)
        except OperationalError:
            LOGGER.info('Failed to update db schema, table=%s',
                        table.name)
        except Exception as e:  # pylint: disable=broad-except
            print (e)
            LOGGER.exception(
                'Unexpected error happened when attempting '
                'to update database schema, table: %s',
                table.name)


def _create_or_drop_columns(column_action, columns, table):
    """Create or drop columns.

    Args:
        column_action (str): Column Action.
        columns (list): A list of columns.
        table (sqlalchemy.schema.Table): The sql alchemy table object.
    """
    column_action = column_action.upper()
    for column in columns:
        try:
            COLUMN_ACTION_MAPPING.get(column_action)(table,
                                                     column)
        except OperationalError:
            LOGGER.info('Failed to update db schema, table=%s',
                        table.name)
        except Exception:  # pylint: disable=broad-except
            LOGGER.exception(
                'Unexpected error happened when attempting '
                'to update database schema, table: %s',
                table.name)


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

    # Create tables if not exists.
    inventory_dao.initialize(SQL_ENGINE)
    scanner_dao.initialize(SQL_ENGINE)

    # Find all the child classes inherited from declarative base class.
    scanner_base_subclasses = _find_subclasses(scanner_dao.BASE)

    inventory_base_subclasses = _find_subclasses(inventory_dao.BASE)
    inventory_base_subclasses.extend([inventory_dao.CaiTemporaryStore])

    DECLARITIVE_BASE_MAPPING = {
        scanner_dao.BASE: scanner_base_subclasses,
        inventory_dao.BASE: inventory_base_subclasses}

    for (declaritive_base,
         base_subclasses) in DECLARITIVE_BASE_MAPPING.iteritems():
        declaritive_base.metadata.bind = SQL_ENGINE
        migrate_schema(declaritive_base, base_subclasses)
