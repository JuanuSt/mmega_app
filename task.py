#!/home/kass/workspaces/mmega_app/mmega_app/venv/bin/python2.7

from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import scoped_session, sessionmaker
import os, sys, subprocess, humanfriendly, tempfile, md5, hashlib
from datetime import datetime
from prettytable import PrettyTable
import time
from rq import get_current_job

# Vars
FNULL = open(os.devnull, 'w')

# path to db
db_path = os.path.join(os.getcwd(),'mmega.db')

# Connect to db
engine = create_engine('sqlite:///%s' % db_path, convert_unicode=True, echo=False)
Base = declarative_base()
Base.metadata.reflect(engine)

##############################################################################################
# mmega.db tables ############################################################################
##############################################################################################
class User(Base):
    __table__ = Base.metadata.tables['user']

class Config(Base):
    __table__ = Base.metadata.tables['config']

class Task(Base):
    __table__ = Base.metadata.tables['task']

class DiskStats(Base):
    __table__ = Base.metadata.tables['disk_stats']

class Files(Base):
    __table__ = Base.metadata.tables['files']

class StateHash(Base):
    __table__ = Base.metadata.tables['state_hash']

class FileStats(Base):
    __table__ = Base.metadata.tables['file_stats']


# Task
def task_example(seconds):
    print seconds
    job = get_current_job()
    print('Starting task')
    for i in range(seconds):
        job.meta['progress'] = 100.0 * i / seconds
        job.save_meta()
        print(i)
        time.sleep(1)
    job.meta['progress'] = 100
    job.save_meta()
    print('Task completed')


def _set_task_progress(progress):
    job = get_current_job()
    if job:
        job.meta['progress'] = progress
        job.save_meta()
        task = Task.query.get(job.get_id())
        if progress >= 100:
            task.complete = True
        db.session.commit()


if __name__ == '__main__':
    # Create db object
    db_session = scoped_session(sessionmaker(bind=engine))


