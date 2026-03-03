from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.schedulers.base import BaseScheduler

__scheduler__: BaseScheduler | None = None


def init():
    """
    Initializes the scheduler.

    :return:
    """
    global __scheduler__

    if __scheduler__ is not None:
        return  # nothing to do here

    __scheduler__ = BackgroundScheduler()

    # jobs
    from backend.jobs import users
    from backend.jobs import sessions

    __scheduler__.add_job(users.job_send_activation_token_email, "interval", seconds=60,
                          id="send_activation_token_email", max_instances=1, coalesce=True, misfire_grace_time=30)
    __scheduler__.add_job(sessions.housekeeping, "interval", minutes=5, id="sessions_housekeeping", max_instances=1,
                          coalesce=True, misfire_grace_time=30)

    __scheduler__.start()


def stop():
    """
    Stops the scheduler.
    """
    __scheduler__.shutdown()
