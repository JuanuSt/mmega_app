#!/home/kass/workspaces/mmega_app/mmega_app/venv/bin/python2.7
###/usr/bin/env python

from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import scoped_session, sessionmaker
import os, sys, subprocess, humanfriendly, tempfile, md5, hashlib
from datetime import datetime
from prettytable import PrettyTable

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

class DiskStats(Base):
    __table__ = Base.metadata.tables['disk_stats']
    
class Files(Base):
    __table__ = Base.metadata.tables['files']

class StateHash(Base):
    __table__ = Base.metadata.tables['state_hash']

class FileStats(Base):
    __table__ = Base.metadata.tables['file_stats']


if __name__ == '__main__':
    # Create db object
    db_session = scoped_session(sessionmaker(bind=engine))

    # Show users
    if sys.argv[1] == 'users':
        users = db_session.query(User).all()
        
        if len(sys.argv) == 3 and sys.argv[2] == 'passwd':
            table_users = PrettyTable(['id', 'username', 'email', 'hashed password'])
            for user in users:
                table_users.add_row([user.id, user.user_name, user.user_email, user.user_password_hash])
        else:
            table_users = PrettyTable(['id', 'username', 'email'])
            for user in users:
                table_users.add_row([user.id, user.user_name, user.user_email])
            
        print table_users

    # Show accounts




