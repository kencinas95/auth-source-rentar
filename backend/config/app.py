import logging.config

from fastapi import FastAPI

from backend.config import datasource
from backend.config import scheduler
from backend.config import settings
from backend.config import templates
from backend.config import oauth2

def lifecycle(_: FastAPI):
    """
    FastAPI application lifecycle.

    :param app: FastAPI instance
    """
    # configure logging
    logging.config.dictConfig(settings.LOGGING)

    # phase: init
    datasource.init()
    templates.init()
    scheduler.init()
    oauth2.init()

    yield

    # phase: close
    scheduler.stop()
    datasource.close()
