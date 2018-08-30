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


class ColumnAction:
    """Column action class."""
    DROP = 'DROP'
    CREATE = 'CREATE'


def create_col(table, col):
    """Create Column.

    Args:
        table (Table): The table object.
        col (Column): The column object."""
    LOGGER.info('Attempting to create column: %s', col.name)
    col.create(table, populate_default=True)


def drop_col(table, col):
    """Create Column.

    Args:
        table (Table): The table object.
        col (Column): The column object."""
    LOGGER.info('Attempting to drop column: %s', col.name)
    col.drop(table)


ColumnActionMap = {ColumnAction.DROP: drop_col,
                   ColumnAction.CREATE: create_col}


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

    schema_update_method_name = 'update_schema'

    for subclass in base_subclasses:
        schema_update = getattr(subclass, schema_update_method_name, None)
        if callable(schema_update) and subclass.__tablename__ in tables:
            LOGGER.info('Updating table %s', subclass.__tablename__)
            # schema_update will require the Table object.
            try:
                table = tables.get(subclass.__tablename__)
                columnMapping = schema_update()
                for columnAction, column in columnMapping.iteritems():
                    columnAction = columnAction.upper()
                    if columnAction in ColumnActionMap:
                        ColumnActionMap.get(columnAction)(table, column)
                    else:
                        LOGGER.warn('Column: %s, ColumnAction %s doesn\'t '
                                    'exist.', column, columnAction)
            except OperationalError:
                LOGGER.info('Failed to update db schema, table=%s',
                            subclass.__tablename__)
            except Exception:
                LOGGER.exception('Unexpected error happened when attempting '
                                 'to update database schema, table: %s',
                                 subclass.__tablename__)


def _find_subclasses(cls):
    results = []
    for sc in cls.__subclasses__():
        results.append(sc)
    return results


if __name__ == '__main__':
    # If the DB connection string is passed in, use that, otherwise
    # fall back to the default DB connection string.
    print (sys.argv)
    DB_CONN_STR = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_DB_CONN_STR

    sql_engine = general_dao.create_engine(DB_CONN_STR,
                                           pool_recycle=3600)

    declaritive_bases = [scanner_dao.BASE, inventory_dao.BASE]

    for base in declaritive_bases:
        migrate_schema(sql_engine, base)
