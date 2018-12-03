# -*- coding: UTF-8 -*-

"""
Script to be executed by mmega automation
"""
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import scoped_session, sessionmaker
import os, sys, subprocess, humanfriendly, tempfile, md5, hashlib
from datetime import datetime

# Vars
FNULL = open(os.devnull, 'w')

# user_id passed when cron command is installed through sys
mmega_user_id = sys.argv[1]

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

##############################################################################################
# megatools ##################################################################################
##############################################################################################
class AccountMega:
    """ Manage mega account through megatool """

    # Initial parameters, always instantiated
    def __init__(self, id, name, email, passwd):
        self.id = id
        self.name = name
        self.email = email
        self.passwd = passwd

    # Method ls
    def df(self):
        # Create tmp megarc file
        tmp = tempfile.NamedTemporaryFile(delete=True)
        tmp.write('[Login]\nUsername = %s\nPassword = %s\n' % (str(self.email), str(self.passwd)))
        tmp.flush()

        command = 'megadf --reload --config=%s' % tmp.name
        test_command = 0

        try:
            subprocess.check_call(command, stdout=FNULL, stderr=subprocess.STDOUT, shell=True)
        except:
            test_command = 1

        if test_command != 0:
            tmp.close()
            return 1
        else:
            result = subprocess.Popen(command, stdout=subprocess.PIPE, shell=True)
            output, err = result.communicate()
            tmp.close()  # deletes tmp megarc file

            # Get data
            df_data_raw = output.split('\n')

            df_total_raw = str(df_data_raw[0]).split(':')
            df_total_bytes = int(str(df_total_raw[1]).strip())

            df_used_raw = str(df_data_raw[1]).split(':')
            df_used_bytes = int(str(df_used_raw[1]).strip())

            df_free_raw = str(df_data_raw[2]).split(':')
            df_free_bytes = int(str(df_free_raw[1]).strip())

            df_total = humanfriendly.format_size(df_total_bytes, binary=True)
            df_used = humanfriendly.format_size(df_used_bytes, binary=True)
            df_free = humanfriendly.format_size(df_free_bytes, binary=True)

            # Return values ready to insert in database
            return (self.id, self.name, df_total_bytes, df_free_bytes, df_used_bytes, df_total, df_free, df_used)

    # Method ls export
    def ls(self):
        # Create tmp megarc file
        tmp = tempfile.NamedTemporaryFile(delete=True)
        tmp.write('[Login]\nUsername = %s\nPassword = %s\n' % (str(self.email), str(self.passwd)))
        tmp.flush()

        command = 'megals --reload --config=%s -R --long --export' % tmp.name
        test_command = 0

        try:
            subprocess.check_call(command, stdout=FNULL, stderr=subprocess.STDOUT, shell=True)
        except:
            test_command = 1

        if test_command != 0:
            tmp.close()
            return 1
        else:
            result = subprocess.Popen(command, stdout=subprocess.PIPE, shell=True)
            output, err = result.communicate()
            tmp.close()  # deletes tmp megarc file

            # @info: the output is raw data, it has to be processed
            return output

def md5sum(filename, blocksize=65536):
    hash = hashlib.md5()
    with open(filename, "rb") as f:
        for block in iter(lambda: f.read(blocksize), b""):
            hash.update(block)
    return hash.hexdigest()

def create_local_hash(local_dir):
        # Test dir read access
    if not local_dir:
        return 0
    elif not os.access(local_dir, os.R_OK):
        return 1
    else:
        # Get list of files (directories are not saved)
        local_files_info = []
        
        for path, subdirs, files in os.walk(local_dir):
            for file_info in files:
                abs_file_path = os.path.join(path, file_info)
                local_files_info.append((abs_file_path, '0', datetime.fromtimestamp(os.stat(abs_file_path).st_mtime).strftime('%Y-%m-%d %H:%M:%S'), os.path.getsize(abs_file_path)))

        # Create tmp file and hash it
        tmp = tempfile.NamedTemporaryFile(delete=False)

        for line in local_files_info:
            tmp.write("{}\n".format(line))
        tmp.flush()

        state_hash = md5sum(tmp.name)
        tmp.close()

        return state_hash

def create_remote_hash(remote_dir):
    # Get files file
    remote_files_try = accmega.ls()

    if remote_files_try == 1:
        return 1
    else:
        # Create hash
        new_remote_hash = md5.new(remote_files_try).hexdigest()
        return new_remote_hash


if __name__ == '__main__':
    # Create db object
    db_session = scoped_session(sessionmaker(bind=engine))
    
    # Get accounts by user_id
    accounts = db_session.query(Config).filter_by(user_id = mmega_user_id).all()
    
    for account in accounts:
        # Get account current state
        current_disk_free_bytes = db_session.query(DiskStats.free_bytes).filter_by(config_id = account.id).scalar()
        try:
            current_local_state_hash = db_session.query(StateHash.state_hash).filter_by(config_id = account.id, file_type = 'local').one()
        except:
            current_local_state_hash = 'init'
        current_remote_state_hash = db_session.query(StateHash.state_hash).filter_by(config_id = account.id, file_type = 'remote').one()
                
        # Create mega handler        
        accmega = AccountMega(account.id, account.name, account.email, account.passwd)
        
        # Get disk stats
        df_data_try = accmega.df()

        if df_data_try == 1:
            print "%s - error getting disk data" % account.name
        else:
            # Test changes
            if df_data_try[3] == current_disk_free_bytes:
                print '%s - is udate by disk data' % account.name
                
                # Get local hash
                if account.local_dir:
                    new_local_hash = create_local_hash(account.local_dir)
                    
                    if new_local_hash and new_local_hash != 1:
                        if unicode(new_local_hash) != current_local_state_hash.state_hash:
                            #if update_automatically:
                            # else Set account local as not updated
                            account_state_hash = db_session.query(StateHash).filter_by(config_id = account.id, file_type = 'local').one()
                            account_state_hash.is_update = False
                            print "%s - set to non updated by local hash" % account.name
                            db_session.commit()
                        else:
                            print "%s - is update by local hash" % account.name
                            
                            # Get remote files hash
                            new_remote_hash = create_remote_hash(account.remote_dir)
                            
                            if new_remote_hash != 1:
                                if unicode(new_remote_hash) != current_remote_state_hash.state_hash:
                                        #if update_automatically:
                                        # else Set account remote as not updated
                                        account_state_hash = db_session.query(StateHash).filter_by(config_id = account.id, file_type = 'remote').one()
                                        account_state_hash.is_update = False
                                        print "%s - set to non updated by remote hash" % account.name
                                        db_session.commit()
                                else:
                                    print "%s - is update by remote hash" % account.name
                            else:
                                print "%s - error getting remote files" % account.name
                    else:
                        print "%s - no local dir or local dir non readable" % account.name
                        
                        # Get remote files hash
                        new_remote_hash = create_remote_hash(account.remote_dir)
                        
                        if new_remote_hash != 1:
                            if unicode(new_remote_hash) != current_remote_state_hash.state_hash:
                                    #if update_automatically:
                                    # else Set account remote as not updated
                                    account_state_hash = db_session.query(StateHash).filter_by(config_id = account.id, file_type = 'remote').one()
                                    account_state_hash.is_update = False
                                    print "%s - set to non updated by remote hash" % account.name
                                    db_session.commit()
                            else:
                                print "%s - is update by remote hash" % account.name
                        else:
                            print "%s - error getting remote files" % account.name
            else:
                #if update_automatically:
                # else Set account remote as not updated
                account_state_hash = db_session.query(StateHash).filter_by(config_id = account.id, file_type = 'remote').one()
                account_state_hash.is_update = False
                print "%s - set to non updated by disk stats" % account.name
                db_session.commit()
