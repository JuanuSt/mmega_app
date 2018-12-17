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

        table_users = PrettyTable(['id', 'username', 'email', 'hashed password'])
        table_users.align['username'] = 'l'
        table_users.align['email'] = 'l'
        table_users.align['hashed password'] = 'l'

        for user in users:
            table_users.add_row([user.id, user.user_name, user.user_email, user.user_password_hash])

        if len(sys.argv) == 3 and sys.argv[2] == 'passwd':
            print(table_users.get_string(fields=['id', 'username', 'email', 'hashed password']))
        else:
            print(table_users.get_string(fields=['id', 'username', 'email']))

    # Show accounts
    if sys.argv[1] == 'accounts':
        accounts = db_session.query(Config).all()

        table_accounts = PrettyTable(['owner', 'name', 'email', 'password', 'local dir', 'remote dir'])
        table_accounts.align['owner'] = 'l'
        table_accounts.align['name'] = 'l'
        table_accounts.align['email'] = 'l'
        table_accounts.align['passwd'] = 'l'
        table_accounts.align['local dir'] = 'l'
        table_accounts.align['remote dir'] = 'l'

        for account in accounts:
            owner = db_session.query(User).filter_by(id = account.user_id ).first()
            table_accounts.add_row([owner.user_name, account.name, account.email, account.passwd, account.local_dir, account.remote_dir])

        if len(sys.argv) == 3 and sys.argv[2] == 'passwd':
            print(table_accounts.get_string(fields=['owner', 'name', 'email', 'password', 'local dir', 'remote dir']))
        else:
            print(table_accounts.get_string(fields=['owner', 'name', 'email', 'local dir', 'remote dir']))

    # Show summary
    if sys.argv[1] == 'summary':
        table_summary = PrettyTable(['owner', 'name', 'total', 'used', '% free', 'local', 'remote', 'updated'])
        table_summary.align['owner'] = 'l'
        table_summary.align['name'] = 'l'
        table_summary.align['total'] = 'r'
        table_summary.align['used'] = 'r'
        table_summary.align['% free'] = 'r'
        table_summary.align['local'] = 'r'
        table_summary.align['remote'] = 'r'
        table_summary.align['updated'] = 'l'
        #table_summary.align['synced'] = 'l'

        users = db_session.query(User).all()

        for user in users:
            owner = user.user_name
            accs = db_session.query(Config).filter_by(user_id = user.id).all()

            for acc in accs:
                # Get disk data
                disk = db_session.query(DiskStats).filter_by(user_id = user.id, config_id = acc.id).first()
                percent_free = 100 * (float(disk.free_bytes) / float(disk.total_bytes))
                p_free = '{0:.2f}'.format(percent_free)
                
                # Get number of files
                files = db_session.query(FileStats).filter_by(user_id = user.id, config_id = acc.id).first()
                
                # Is update
                state_local = db_session.query(StateHash).filter_by(user_id = user.id, config_id = acc.id, file_type = 'local').first()
                state_remote = db_session.query(StateHash).filter_by(user_id = user.id, config_id = acc.id, file_type = 'remote').first()
                
                if state_local.is_update and state_remote.is_update:
                    updated = 'yes'
                else:
                    updated = 'no'
                
                table_summary.add_row([owner, acc.name, disk.total, disk.used, p_free, files.local, files.remote, updated])
        
        print table_summary

    # Show files
    if sys.argv[1] == 'files':
        table_files = PrettyTable(['owner', 'account', 'path', 'filename', 'size', 'location', 'link', 'mod. data'])
        table_files.align['owner'] = 'l'
        table_files.align['account'] = 'l'
        table_files.align['path'] = 'l'
        table_files.align['filename'] = 'l'
        table_files.align['size'] = 'r'
        table_files.align['location'] = 'l'
        table_files.align['link'] = 'l'
        table_files.align[' mod. date'] = 'l'
        
        # Get accounts
        acc_names = []
        accounts = db_session.query(Config).all()
        for acc in accounts:
            acc_names.append(acc.name)

        # Show files        
        if len(sys.argv) == 3 or len(sys.argv) == 4 or len(sys.argv) == 5 and sys.argv[2] in acc_names:
            acc = db_session.query(Config).filter_by(name = sys.argv[2]).first()
            usr = db_session.query(User).filter_by(id = acc.user_id).first()

            if len(sys.argv) == 4 and sys.argv[3] == 'local':
                files = db_session.query(Files).filter_by(is_dir = False, config_id = acc.id, user_id = usr.id, file_type = 'local').all()            
                for f in files:
                    table_files.add_row([usr.user_name, acc.name, f.path, f.filename, f.size, f.file_type, f.link, f.mod_date])
                table_files.sortby = 'filename'
                print "Local files of account %s owned by %s" % (acc.name, usr.user_name)
                print(table_files.get_string(fields=['filename', 'size', 'mod. data']))
            elif len(sys.argv) == 4 or len(sys.argv) == 5 and sys.argv[3] == 'remote':
                files = db_session.query(Files).filter_by(is_dir = False, config_id = acc.id, user_id = usr.id, file_type = 'remote').all()            
                for f in files:
                    table_files.add_row([usr.user_name, acc.name, f.path, f.filename, f.size, f.file_type, f.link, f.mod_date])
                table_files.sortby = 'filename'
                print "Remote files of account %s owned by %s" % (acc.name, usr.user_name)
                if len(sys.argv) == 5 and sys.argv[4] == 'link':
                    print(table_files.get_string(fields=['filename', 'size', 'link', 'mod. data']))
                else:
                    print(table_files.get_string(fields=['filename', 'size', 'mod. data']))
            else:
                files = db_session.query(Files).filter_by(is_dir = False, config_id = acc.id, user_id = usr.id).all()            
                for f in files:
                    table_files.add_row([usr.user_name, acc.name, f.path, f.filename, f.size, f.file_type, f.link, f.mod_date])
                table_files.sortby = 'filename'
                print "Files in account %s owned by %s" % (acc.name, usr.user_name)
                print(table_files.get_string(fields=['filename', 'size', 'location', 'mod. data']))
        else:
            files = db_session.query(Files).filter_by(is_dir = False).all()
            for f in files:
                owner = db_session.query(User).filter_by(id = f.user_id).first()
                acc = db_session.query(Config).filter_by(id = f.config_id).first()
                table_files.add_row([owner.user_name, acc.name, f.file_type, f.path, f.filename, f.size, f.link, f.mod_date])
            table_files.sortby = 'owner'
            print table_files
        
            
            
