from contextlib import contextmanager

import mongodb_odm as odm
import pymongo

from backend.config import settings

__datasource__: pymongo.MongoClient | None = None


def init():
    """
    Initializes the mongodb connection.
    """
    global __datasource__

    if not __datasource__:
        __datasource__ = odm.connect(settings.MDB_CONNECTION_URL, databases={settings.MDB_DATABASE_NAME})
        odm.apply_indexes()


def close():
    """
    Closes the mongodb connection.
    """
    global __datasource__

    if __datasource__:
        odm.disconnect()
        __datasource__.close()


def collection(name: str, db_name: str | None = None) -> pymongo.collection.Collection:
    """
    Returns a pymongo.collection.Collection object.

    :param name: collection name
    :param db_name: optional database name
    :return: pymongo.collection.Collection object
    """
    if not __datasource__:
        raise SystemError("MongoDB client is not initialized, unable to get collection.")

    if db_name is None:
        db_name = settings.MDB_DATABASE_NAME

    return __datasource__.get_database(db_name).get_collection(name)


@contextmanager
def dbsession():
    if not __datasource__:
        raise SystemError("MongoDB client is not initialized, unable to get session.")

    session = __datasource__.start_session()
    try:
        yield session
    finally:
        session.end_session()
