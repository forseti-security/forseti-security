import sys

from sqlalchemy.exc import OperationalError

import google.cloud.forseti.services.scanner.dao as scanner_dao
import google.cloud.forseti.services.inventory.storage as inventory_dao
import google.cloud.forseti.services.dao as general_dao

from google.cloud.forseti.common.util import logger


DEFAULT_DB_CONN_STR = 'mysql://root@127.0.0.1:3306/forseti_security'
LOGGER = logger.get_logger(__name__)


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

    schema_update_method_name = 'schema_update'

    for subclass in base_subclasses:
        schema_update = getattr(subclass, schema_update_method_name, None)
        if callable(schema_update) and subclass.__tablename__ in tables:
            LOGGER.info('Updating table %s', subclass.__tablename__)
            # schema_update will require the Table object.
            try:
                schema_update(tables.get(subclass.__tablename__))
            except OperationalError:
                LOGGER.info('Failed to update db schema, table=%s',
                            subclass.__tablename__)
            except Exception as e:
                LOGGER.error(e)


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

    # Upgrade Scanner tables.
    migrate_schema(sql_engine, scanner_dao.BASE)

    # Upgrade Inventory tables.
    migrate_schema(sql_engine, inventory_dao.BASE)
