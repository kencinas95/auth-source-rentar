import logging

from pymongo.synchronous.collection import Collection

from backend import utils
from backend.config import datasource
from backend.config.settings import AUTH_SESSION_IDLE_LIMIT, MDB_MAX_BATCH_SIZE
from backend.config.settings import AUTH_SESSION_STORAGE_AUDIT_TIME_LIMIT
from backend.models import Session, UserSessionStatus, User, UserStatus

log = logging.getLogger("backend.jobs.sessions")


def helper_orphan_searcher(mdb_sessions: Collection):
    """
    Helper function for orphan sessions.

    :param mdb_sessions: mdb sessions collection instance
    """
    query_pipeline = [{"$match": {"status": UserSessionStatus.ACTIVE.value}}, {
        "$lookup": {"from": User.ODMConfig.collection_name, "localField": "uid", "foreignField": "_id", "as": "user"}},
                      {"$unwind": {"path": "$user", "preserveNullAndEmptyArrays": True}},
                      {"$match": {"$or": [{"user": None}, {"user.status": {"$ne": UserStatus.ACTIVE.value}}]}},
                      {"$project": {"_id": 1}}, {"$limit": MDB_MAX_BATCH_SIZE}]
    while True:
        orphans = [orphan["_id"] for orphan in mdb_sessions.aggregate(query_pipeline)]
        if not orphans:
            break
        mdb_sessions.update_many({"_id": {"$in": orphans}}, {"$set": {"status": UserSessionStatus.ORPHAN.value},
                                                             "$currentDate": {"revoked_at": True}})


def housekeeping():
    """
    Housekeeping job for sessions.
    """
    log.info("Starting housekeeping for sessions")

    mdb_sessions = datasource.collection(Session.ODMConfig.collection_name)

    utcnow = utils.utcnow()

    # update expired sessions
    log.info("Revoking expired sessions")
    mdb_sessions.update_many({"status": UserSessionStatus.ACTIVE.value, "expires_at": {"$lt": utcnow}},
                             {"$set": {"status": UserSessionStatus.EXPIRED.value},
                              "$currentDate": {"revoked_at": True}})

    # mark every session as IDLE_EXPIRED if they weren't refreshed within the idle time limit
    log.info("Revoking idle expired sessions")
    mdb_sessions.update_many(
        {"status": UserSessionStatus.ACTIVE.value, "last_seen_at": {"$lt": utcnow - AUTH_SESSION_IDLE_LIMIT}},
        {"$set": {"status": UserSessionStatus.IDLE_EXPIRED.value}, "$currentDate": {"revoked_at": True}})

    # mark as orphan if user does not exist or is not active
    log.info("Searching for orphan sessions")
    helper_orphan_searcher(mdb_sessions)

    # hard delete for sessions older than the storage audit time limit
    log.info("Deleting old sessions")
    mdb_sessions.delete_many({"created_at": {"$lt": utcnow - AUTH_SESSION_STORAGE_AUDIT_TIME_LIMIT}})

    log.info("Housekeeping for session is completed")
