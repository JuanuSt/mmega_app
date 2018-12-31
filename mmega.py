# -*- coding: UTF-8 -*-

# Imports [see requeriments.txt]
import os, sys, tablib, subprocess, humanfriendly, tempfile, md5, hashlib, shutil, time
from datetime import datetime, date
from crontab import CronTab
from flask import Flask, url_for, render_template, request, redirect, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, current_user, login_user, logout_user, login_required
from flask_wtf import FlaskForm
from flask_wtf.file import FileField
from wtforms import StringField, PasswordField, BooleanField, SubmitField, SelectField, RadioField, TimeField, IntegerField
from wtforms.validators import ValidationError, InputRequired, DataRequired, Email, Length, EqualTo
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
import socket
from urlparse import urlparse
from redis import Redis
import rq
from rq import Worker, get_current_job
#from threading import Thread

# Define the WSGI application object
app = Flask(__name__, instance_relative_config=True)

# Configuration
#app.config.from_object('config')    # Load the default configuration (prod)
app.config.from_pyfile('config.py') # Load the configuration from the instance folder (dev)

# Other app config
CONFIG_ALLOWED_EXTENSIONS = ['txt', 'csv']
FNULL = open(os.devnull, 'w')

reload(sys)
sys.setdefaultencoding('utf8')

# Define the database object
db = SQLAlchemy(app)

# Redis
app.redis = Redis.from_url(app.config['REDIS_URL'])  # Connect to redis server
app.task_queue = rq.Queue('mmega-tasks', connection=app.redis)  # Create a queue
#app.worker = rq.Worker('mmega-task', connection=app.redis)
#app.worker.work()


##############################################################################################
# Models #####################################################################################
##############################################################################################
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_name = db.Column(db.String(64), index=True, unique=True)
    user_email = db.Column(db.String(120), index=True)
    user_password_hash = db.Column(db.String(128))
    tasks = db.relationship('Task', backref='user', lazy='dynamic')

    def __repr__(self):
        return '<User {}>'.format(self.user_name)

    # Register methods
    def set_password(self, password):
        self.user_password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.user_password_hash, password)

    # Redis methods
    def launch_task(self, name, description, *args, **kwargs):
        print args
        rq_job = app.task_queue.enqueue('tasks.' + name, self.id, *args, **kwargs)
        task = Task(id=rq_job.get_id(), name=name, description=description, user=self)
        db.session.add(task)
        return task

    def get_tasks_in_progress(self):
        return Task.query.filter_by(user=self, complete=False).all()

    def get_task_in_progress(self, name):
        return Task.query.filter_by(name=name, user=self, complete=False).first()

class Config(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    name = db.Column(db.String(64), nullable=False)
    email = db.Column(db.String(120), nullable=False)
    passwd = db.Column(db.String(120), nullable=False)
    local_dir = db.Column(db.String(4096), nullable=True)
    local_links = db.Column(db.Boolean)
    remote_dir = db.Column(db.String(4096), nullable=False)
    created = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    def __repr__(self):
        return '<Config %r>' % self.name

class DiskStats(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    config_id = db.Column(db.Integer, db.ForeignKey('config.id'), nullable=False)
    name = db.Column(db.String(255), nullable=False)
    total_bytes = db.Column(db.BigInteger)
    free_bytes = db.Column(db.BigInteger)
    used_bytes = db.Column(db.BigInteger)
    total = db.Column(db.String(255))
    free = db.Column(db.String(255))
    used = db.Column(db.String(255))
    last_update = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    def __repr__(self):
        return '<DiskStats %r>' % self.name

class Files(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    config_id = db.Column(db.Integer, db.ForeignKey('config.id'), nullable=False)
    is_dir = db.Column(db.Boolean) # dir or not
    file_type = db.Column(db.String(20)) # remote, local, to_up, to_down
    link = db.Column(db.String(255))
    size_bytes = db.Column(db.BigInteger)
    size = db.Column(db.String(255))
    mod_date = db.Column(db.DateTime)
    path = db.Column(db.String(4096))
    filename = db.Column(db.String(255))

class StateHash(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    config_id = db.Column(db.Integer, db.ForeignKey('config.id'), nullable=False)
    file_type = db.Column(db.String(20), nullable=False) # remote, local,
    state_hash = db.Column(db.String(32), nullable=False)
    is_update = db.Column(db.Boolean)
    last_update = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

class FileStats(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    config_id = db.Column(db.Integer, db.ForeignKey('config.id'), nullable=False)
    name = db.Column(db.String(255), unique=True, nullable=False)
    local = db.Column(db.Integer)
    remote = db.Column(db.Integer)
    to_down = db.Column(db.Integer)
    to_up = db.Column(db.Integer)
    last_update = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

class Task(db.Model):
    id = db.Column(db.String(36), primary_key=True) # id as string, using rq job identifiers
    name = db.Column(db.String(128), index=True)
    description = db.Column(db.String(128))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    complete = db.Column(db.Boolean, default=False)

    def get_rq_job(self):
        try:
            rq_job = rq.job.Job.fetch(self.id, connection=app.redis)
        except (redis.exceptions.RedisError, rq.exceptions.NoSuchJobError):
            return None
        return rq_job

    def get_progress(self):
        job = self.get_rq_job()
        return job.meta.get('progress', 0) if job is not None else 100

# Create model tables
db.create_all()


##############################################################################################
# Forms ######################################################################################
##############################################################################################
class RegistrationForm(FlaskForm):
    username = StringField('username', validators=[DataRequired(), Length(1, 64)], render_kw={"placeholder": "choose your nickname"})
    email = StringField('email', validators=[Length(0, 120)], render_kw={"placeholder": "not necessary"})
    password = PasswordField('password', validators=[DataRequired(), Length(0, 12)], render_kw={"placeholder": "max. 12 chars"})
    password2 = PasswordField('repeat password', validators=[DataRequired(), Length(0, 12), EqualTo('password')], render_kw={"placeholder": "equal to password"})
    submit = SubmitField('Register')

    def validate_username(self, username):
        user = User.query.filter_by(user_name=username.data).first()
        if user is not None:
            raise ValidationError('Please use a different username.')

class UserConfigForm(FlaskForm):
    user_name = StringField('username', validators=[DataRequired(), Length(1, 64)], render_kw={"placeholder": "change your nickname"})
    user_email = StringField('email', validators=[Length(0, 120)], render_kw={"placeholder": "not used"})
    user_current_password = PasswordField('current password', validators=[DataRequired(), Length(0, 12)], render_kw={"placeholder": "mandatory to make changes"})
    new_password = PasswordField('new password', validators=[Length(0, 12)], render_kw={"placeholder": "max. 12 chars"})
    new_password2 = PasswordField('repeat new password', validators=[Length(0, 12), EqualTo('new_password')], render_kw={"placeholder": "equal to new password"})
    submit = SubmitField('change')

    def validate_username(self, username):
        user = User.query.filter_by(user_name=username.data).first()
        if user is not None:
            raise ValidationError('Please use a different username.')

class LoginForm(FlaskForm):
    username = StringField('username', validators=[DataRequired(), Length(1, 64)], render_kw={"placeholder": "your nickname"})
    password = PasswordField('password', validators=[DataRequired(), Length(0, 12)], render_kw={"placeholder": "your password"})
    remember_me = BooleanField('keep me logged', default="checked")
    submit = SubmitField('Sign In')

class AddAccountForm(FlaskForm):
    name = StringField('account name', validators=[DataRequired(), Length(0, 64)], render_kw={"placeholder": "account nickname"})
    email = StringField('mega email', validators=[DataRequired(), Email(), Length(0, 120)], render_kw={"placeholder": "mega.nz registered email"})  # validators=[DataRequired(), Email()])
    passwd = PasswordField('mega password', validators=[DataRequired(), Length(0, 120)] , render_kw={"placeholder": "mega.nz password"})
    local_dir = StringField('local dir', validators=[Length(0, 4096)], render_kw={"placeholder": "/accesible/local/dir"})
    local_links = BooleanField('create local links', default=False)
    remote_dir = StringField('remote dir', default='/Root', validators=[DataRequired(), Length(0, 4096)], render_kw={"placeholder": "/Root/remote/dir"})
    add_account_button = SubmitField('Add account')

class ConfigForm(FlaskForm):
    name = StringField('account name', validators=[DataRequired(), Length(0, 64)], render_kw={"placeholder": "nickname"})
    email = StringField('mega email', validators=[DataRequired(), Email(), Length(0, 120)], render_kw={"placeholder": "mega.nz registered mail"})  # validators=[ Email(),
    passwd = PasswordField('mega password', validators=[Length(0, 120)], render_kw={"placeholder": "not shown"})
    remote_dir = StringField('remote dir', validators=[DataRequired(), Length(0, 4096)])
    local_dir = StringField('local dir', validators=[Length(0, 4096)])
    local_links = BooleanField('create local links')
    change_config_button = SubmitField('change')

class DeleteAccountForm(FlaskForm):
    name = StringField('account name')
    email = StringField('mega email')
    passwd = PasswordField('mega password', render_kw={"placeholder": "not shown"})
    remote_dir = StringField('remote dir')
    local_dir = StringField('local dir')
    delete_account_button = SubmitField('delete')

class UploadConfigForm(FlaskForm):
    file = FileField(validators=[DataRequired()])

class UploadFileForm(FlaskForm):
    file = FileField(validators=[DataRequired()])
    remote_dir_dst = StringField('remote dir', validators=[DataRequired(), Length(0, 4096)], render_kw={"placeholder": "/remote/dir/target"})

class CopyForm(FlaskForm):
    file_to_move = StringField('file to copy or move', validators=[DataRequired(), Length(0, 255)])
    move_check = BooleanField('move')
    acc_dst = SelectField('destination account', coerce=int, validators=[InputRequired()])
    remote_dir_dst = StringField('remote dir', default='/Root', validators=[DataRequired(), Length(0, 4096)], render_kw={"placeholder": "/remote/dir/target"})
    move_button = SubmitField('Copy / Move')

class SearchForm(FlaskForm):
    string_to_search = StringField('string to search', validators=[DataRequired(), Length(0, 255)])
    accounts = SelectField('account', coerce=int, validators=[InputRequired()], default='all')
    places = RadioField('places', choices=[('local_search', 'local'),
                                           ('remote_search', 'remote'),
                                           ('full_search', 'both')], validators=[DataRequired()], default='remote_search')
    search_button = SubmitField('Search')

class AutomationForm(FlaskForm):
    cron_options = RadioField('contact every', choices=[
        ('never', 'never'),
        ('every_hour', 'hour'),
        ('every_day', 'day'),
        ('every_week', 'week'),
        ('every_month', 'month'),
        ('every_year', 'year')
        ], validators=[DataRequired()], default='every_month')
    hour = IntegerField('hour', validators=[DataRequired()], default='22')
    minute = IntegerField('minute', validators=[DataRequired()], default='00')
    set_button = SubmitField('Set')


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

    # Method df
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
            flash('%s - failed to connect to mega' % (self.name), 'error')
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
    def ls(self, remote_dir):
        # Create tmp megarc file
        tmp = tempfile.NamedTemporaryFile(delete=True)
        tmp.write('[Login]\nUsername = %s\nPassword = %s\n' % (str(self.email), str(self.passwd)))
        tmp.flush()

        command = "megals --reload --config=%s -R '%s' --long --export" % (tmp.name, remote_dir)
        test_command = 0

        try:
            subprocess.check_call(command, stdout=FNULL, stderr=subprocess.STDOUT, shell=True)
        except:
            test_command = 1

        if test_command != 0:
            flash('%s - failed to connect to mega' % (self.name), 'error')
            tmp.close()
            return 1
        else:
            result = subprocess.Popen(command, stdout=subprocess.PIPE, shell=True)
            output, err = result.communicate()
            tmp.close()  # deletes tmp megarc file

            # @info: the output is raw data, it has to be processed
            return output

    # Method put
    # @TODO check command
    def put(self, local_file_path, remote_path):
        # Create tmp megarc file
        tmp = tempfile.NamedTemporaryFile(delete=True)
        tmp.write('[Login]\nUsername = %s\nPassword = %s\n' % (str(self.email), str(self.passwd)))
        tmp.flush()

        command = "megaput --reload --no-progress --config=%s '%s' --path='%s' > /dev/null 2>&1" % (tmp.name, local_file_path, remote_path)
        os.system(command)
        tmp.close()  # deletes tmp megarc file

    # Metrod rm
    # @TODO check command
    def rm(self, remote_file_path):
        # Create tmp megarc file
        tmp = tempfile.NamedTemporaryFile(delete=True)
        tmp.write('[Login]\nUsername = %s\nPassword = %s\n' % (str(self.email), str(self.passwd)))
        tmp.flush()

        command = "megarm --reload --config=%s '%s' " % (tmp.name, remote_file_path)
        os.system(command)
        tmp.close()  # deletes tmp megarc file


##############################################################################################
# Checks and commons functions ###############################################################
##############################################################################################
# Login manager init
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"
login_manager.session_protection = "strong" # or basic
login_manager.login_message = "Please log in to access this page."
login_manager.login_message_category = "warning"

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)

# Check allowed ext in uploaded config file
def allowed_config_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in CONFIG_ALLOWED_EXTENSIONS

def md5sum(filename, blocksize=65536):
    hash = hashlib.md5()
    with open(filename, "rb") as f:
        for block in iter(lambda: f.read(blocksize), b""):
            hash.update(block)
    return hash.hexdigest()

# Insert disk data (required in first run)
def get_disk_data(id):
    # Get config parameters from db or session
    config = Config.query.filter_by(id=id).first()

    id = config.id
    name = config.name
    email = config.email
    passwd = config.passwd

    # Instanciate accountmega handler
    accmega = AccountMega(id, name, email, passwd)

    # Update disk data
    df_data_try = accmega.df()

    if df_data_try == 1:
        # Delete current account disk data
        DiskStats.query.filter_by(config_id=config.id).delete()
        db.session.rollback()

        flash('%s - failed to update disk data' % name, 'error')
        return 1
    else:
        # Add row to disk data
        df_data = DiskStats(
                user_id = config.user_id,
                config_id = df_data_try[0],
                name = df_data_try[1], 
                total_bytes = df_data_try[2], 
                free_bytes = df_data_try[3],
                used_bytes = df_data_try[4],
                total = df_data_try[5],
                free = df_data_try[6],
                used = df_data_try[7])
        db.session.add(df_data)
        db.session.commit()

        flash('%s - disk data updated' % df_data_try[1], 'success')

# Just update disk data
def update_disk_data(id):
    # Get config parameters from db or session
    config = Config.query.filter_by(id=id).first()

    id = config.id
    name = config.name
    email = config.email
    passwd = config.passwd

    # Instanciate accountmega handler
    accmega = AccountMega(id, name, email, passwd)

    # Get disk data
    df_data_try = accmega.df()

    if df_data_try == 1:
        # Delete current account files
        DiskStats.query.filter_by(config_id=config.id).delete()
        db.session.rollback()
        flash('%s - update disk data failed' % name, 'error')
        return 1
    else:
        # Test changes
        current_disk_data = DiskStats.query.filter_by(config_id=config.id).first()

        if df_data_try[3] == current_disk_data.free_bytes:
            pass
            flash('%s - disk data are already updated' % name, 'info')
        else: 
            current_disk_data.user_id = config.user_id
            current_disk_data.config_id = df_data_try[0]
            current_disk_data.name = df_data_try[1]
            current_disk_data.total_bytes = df_data_try[2]
            current_disk_data.free_bytes = df_data_try[3]
            current_disk_data.used_bytes = df_data_try[4]
            current_disk_data.total = df_data_try[5]
            current_disk_data.free = df_data_try[6]
            current_disk_data.used = df_data_try[7]

            db.session.commit()
            flash('%s - disk data updated' % name, 'success')

# Insert remote file. Long time exec. 
def get_remote_files(id):
    # Get config parameters from db or session
    config = Config.query.filter_by(id=id).first()

    id = config.id
    name = config.name
    email = config.email
    passwd = config.passwd
    remote_dir = config.remote_dir

    # Delete current account remote files
    Files.query.filter_by(config_id=config.id, file_type = 'remote').delete() # to be commited after test

    # Instanciate accountmega handler
    accmega = AccountMega(id, name, email, passwd)

    # Get files file
    remote_files_try = accmega.ls(remote_dir)

    if remote_files_try == 1:
        # Do not delete files
        db.session.rollback()

        flash('%s - error getting remote files' % name, 'error')
        return 1
    else:
        # Get state hash
        current_state = StateHash.query.filter_by(user_id = config.user_id, config_id = config.id, file_type = 'remote').first()

        # Fisrt run
        if not current_state:
            # Insert init hash
            init_hash = StateHash(user_id = config.user_id, config_id = config.id, file_type = 'remote', state_hash = 'init',is_update = False)
            db.session.add(init_hash)
            current_state = StateHash.query.filter_by(user_id = config.user_id, config_id = config.id, file_type = 'remote').first()

        # Create hash
        state_hash = md5.new(remote_files_try).hexdigest()

        if unicode(state_hash) != current_state.state_hash:
            # Delete current remote files
            db.session.commit()

            # Update state hash (is_update after insert files)
            new_state_hash = StateHash.query.filter_by(config_id=config.id, file_type = 'remote').first()
            new_state_hash.user_id = config.user_id
            new_state_hash.config_id = config.id
            new_state_hash.file_type = 'remote'
            new_state_hash.state_hash = state_hash

            # Extract info from megals output
            remote_files_try_raw = remote_files_try.splitlines()

            for line in remote_files_try_raw:
                file_data_raw = line.split(None, 7)

                if file_data_raw[3] == str(0) or file_data_raw[2] == str(1):
                    # file
                    if file_data_raw[3] == str(0):
                        is_dir = False
                        file_type = 'remote'
                        link = file_data_raw[0]

                        if file_data_raw[4] == '-':
                            size_bytes = 0
                        else:
                            size_bytes = file_data_raw[4]

                        mod_date = datetime.strptime(file_data_raw[5] + " " + file_data_raw[6], '%Y-%m-%d %H:%M:%S')
                        path = file_data_raw[7].decode('utf-8')

                    # directory
                    elif file_data_raw[2] == str(1):
                        is_dir = True
                        file_type = 'remote'
                        link = ""
                        size_bytes = ""
                        mod_date = datetime.strptime(file_data_raw[4] + ' ' + file_data_raw[5], '%Y-%m-%d %H:%M:%S')
                        path = file_data_raw[6].decode('utf-8')

                    else:
                        is_dir = True
                        file_type = 'error'
                        link = ""
                        size_bytes = ""
                        mod_date = ""
                        path = ""

                    # Insert data into db
                    file_info  = Files(
                            user_id = config.user_id,
                            config_id = config.id,
                            is_dir = is_dir,
                            file_type = file_type,
                            link = link or None,
                            size_bytes = size_bytes or None,
                            size = humanfriendly.format_size(int(size_bytes or 0 ), binary=True) or None,
                            mod_date = mod_date,
                            path = path,
                            filename = path.split('/', len(path.split('/', -1)))[-1].rstrip('\'') or None
                            )
                    db.session.add(file_info)

            new_state_hash.is_update = True    
            db.session.commit()

            flash('%s - remote files have been updated' % name, 'success')
        else:
            # Do not delete files
            db.session.rollback()
            flash('%s - remote files are already updated' % name, 'info')

# Insert local files
def get_local_files(id):
    # Get config parameters from db or session
    config = Config.query.filter_by(id=id).first()

    id = config.id
    name = config.name
    email = config.email
    passwd = config.passwd
    local_dir = config.local_dir

    # Delete current account local files
    Files.query.filter_by(config_id=config.id, file_type = 'local').delete() # to be commited after test

    # Test dir read access
    if not local_dir:
        # Do not delete files
        db.session.rollback()
        pass
    elif not os.access(local_dir, os.R_OK):
        # Do not delete files
        db.session.rollback()

        flash("%s - local directory %s is not readable" % (name, local_dir), 'error')
        return 1
    else:
        # Get list of files (directories are not saved)
        local_files_info = []
        
        for path, subdirs, files in os.walk(local_dir):
            for file_info in files:
                if '.debris' in path:
                    pass
                else:
                    abs_file_path = os.path.join(path, file_info)
                    local_files_info.append((abs_file_path, '0', datetime.fromtimestamp(os.stat(abs_file_path).st_mtime).strftime('%Y-%m-%d %H:%M:%S'), os.path.getsize(abs_file_path)))

        # Create tmp file and hash it
        tmp = tempfile.NamedTemporaryFile(delete=True)

        for line in local_files_info:
            tmp.write("{}\n".format(line))
        tmp.flush()

        state_hash = md5sum(tmp.name)
        tmp.close()

        # Get state hash
        current_state = StateHash.query.filter_by(user_id = config.user_id, config_id = config.id, file_type = 'local').first()

        # Fisrt run
        if not current_state:
            # Insert init hash
            init_hash = StateHash(
                            user_id = config.user_id,
                            config_id = config.id,
                            file_type = 'local',
                            state_hash = 'init',
                            is_update = False
                            )
            db.session.add(init_hash)
            current_state = StateHash.query.filter_by(user_id = config.user_id, config_id = config.id, file_type = 'local').first()

        if unicode(state_hash) != current_state.state_hash:
            # Delete current local files
            db.session.commit()
    
            # Update state hash
            new_state_hash = StateHash.query.filter_by(config_id=config.id, file_type = 'local').first()
            new_state_hash.user_id = config.user_id
            new_state_hash.config_id = config.id
            new_state_hash.file_type = 'local'
            new_state_hash.state_hash = state_hash

            # Insert data into db
            for line in local_files_info:
                if line[1] == '1':  # dir, not done
                    file_info  = Files(
                            user_id = config.user_id,
                            config_id = config.id,
                            is_dir = 1,
                            file_type = 'local',
                            link = None,
                            size_bytes = None,
                            size = None,
                            mod_date = datetime.strptime(line[2],'%Y-%m-%d %H:%M:%S'),
                            path = line[0]
                            )
                    db.session.add(file_info)
                elif line[1] == '0':  # file
                    file_info  = Files(
                            user_id = config.user_id,
                            config_id = config.id,
                            is_dir = 0,
                            file_type = 'local',
                            link = None,
                            size_bytes = line[3],
                            size = humanfriendly.format_size(int(line[3] or 0 ), binary=True) or None,
                            mod_date = datetime.strptime(line[2], '%Y-%m-%d %H:%M:%S'),
                            path = line[0],
                            filename = line[0].split('/', len(line[0].split('/', -1)))[-1].rstrip('\'') or None
                            )
                    db.session.add(file_info)

            tmp.close()
            new_state_hash.is_update = True
            db.session.commit()
            flash('%s - local files have been updated' % name, 'success')
        else:
            # Do not delete files
            db.session.rollback()
            flash('%s - local files are already updated' % name, 'info')

def update_file_stats(id):
    # Get config parameters from db or session
    config = Config.query.filter_by(id=id).first()

    id = config.id
    name = config.name
    email = config.email

    # Calculate
    num_remote_files = Files.query.filter_by(config_id=config.id, is_dir=False, file_type="remote").count()
    num_local_files = Files.query.filter_by(config_id=config.id, is_dir=False, file_type="local").count()
    num_to_up_files = Files.query.filter_by(config_id=config.id, is_dir=False, file_type="to_up").count()
    num_to_down_files = Files.query.filter_by(config_id=config.id, is_dir=False, file_type="to_down").count()

    # test db entry
    if FileStats.query.filter_by(config_id=config.id).first():
        # Update
        new_file_stats = FileStats.query.filter_by(config_id=config.id).first()
        new_file_stats.user_id = config.user_id
        new_file_stats.config_id = config.id
        new_file_stats.name = name
        new_file_stats.local = num_local_files or None
        new_file_stats.remote = num_remote_files or None
        new_file_stats.to_up = num_to_up_files or None
        new_file_stats.to_down = num_to_up_files or None

    else:
        # Add
        files_stats_info = FileStats(user_id = config.user_id, config_id = config.id,name = name,
                            local = num_local_files or None, remote = num_remote_files or None,
                            to_up = num_to_up_files or None,to_down = num_to_up_files or None
                            )
        db.session.add(files_stats_info)

    db.session.commit()

# Kill mega-cmd-server processes (sessions remain open)
def kill_mega_cmd_server():
    mega_server_pids = subprocess.Popen(['pgrep','mega-cmd-server'], stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    for mega_server_pid in mega_server_pids:
        if mega_server_pid:
            os.system('kill %s' % mega_server_pid.rstrip())

# Kill sessions (one account)
def kill_sessions(config_id):
    # Get account params
    acc = Config.query.filter_by(id = config_id).one()

    # Log in 
    passwd = '\'' + acc.passwd + '\''
    command = 'mega-login %s %s' % (acc.email, passwd)
    os.system(command)

    # Kill all sessions
    command = 'mega-killsession -a'
    os.system(command)

    # Log out
    command = 'mega-logout'
    os.system(command)

def get_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # doesn't even have to be reachable
        s.connect(('10.255.255.255', 1))
        IP = s.getsockname()[0]
    except:
        IP = '127.0.0.1'
    finally:
        s.close()
    return IP


# Set task progress (Redis)
def _set_task_progress(progress):
    job = get_current_job()
    if job:
        job.meta['progress'] = progress
        job.save_meta()
        task = Task.query.get(job.get_id())
        #task.user.add_notification('task_progress', {'task_id': job.get_id(),'progress': progress})
        # Use flash
        if progress >= 100:
            task.complete = True
        db.session.commit()


##############################################################################################
# Tasks ######################################################################################
##############################################################################################

def task_update(app, config_id):
    with app.app_context():
        print "Starting task update"
    
        get_remote_files(config_id)
        get_local_files(config_id)
        update_file_stats(config_id)
        update_disk_data(config_id)
    
        #name = "tst"
        flash('%s - is updated' % name, 'success')
        #return redirect('/home')
    
        print "Task update completed"

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
    task_obj = Task.query.filter_by(id = job.get_id())
    task_obj.complete = True

##############################################################################################
# Routes #####################################################################################
##############################################################################################
@app.route('/')
@app.route('/index')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    else:
        return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))

    register_form = RegistrationForm()

    if request.method == 'POST':

        if register_form.validate_on_submit():
            user = User(user_name=register_form.username.data, user_email=register_form.email.data)
            user.set_password(register_form.password.data)
            db.session.add(user)
            db.session.commit()
            flash('Congratulations, you are registered as %s' % register_form.username.data, 'success')
            return redirect(url_for('login'))
        else:
            flash(register_form.errors, 'error')

    return render_template('register_form.html', title='register', register_form=register_form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))

    login_form = LoginForm()

    if request.method == 'POST':

        if login_form.validate_on_submit():
            user = User.query.filter_by(user_name=login_form.username.data).first()

            if user is None:
                flash('Username does not exist. You have to register it.', 'info')
                return redirect(url_for('login'))
                
            elif not user.check_password(login_form.password.data):
                flash('Invalid username or password', 'error')
                return redirect(url_for('login'))

            login_user(user, remember=login_form.remember_me.data)

            # Init mega-cmd-server
            #accs = Config.query.all()
            #if accs:
            #    for acc in accs:
            #        kill_sessions(acc.id)

            flash('Logged in successfully as {}'.format(login_form.username.data), 'success')

            return redirect(url_for('home'))

    return render_template('login_form.html', title='login', login_form = login_form)

@app.route('/user_config_form', methods=['GET', 'POST'])
@login_required
def user_config():
    user_config_form = UserConfigForm()

    current_user_from_db = User.query.filter_by(id = current_user.id).first()

    if request.method == 'GET':
        user_config_form.user_name.data = current_user_from_db.user_name
        user_config_form.user_email.data = current_user_from_db.user_email

    if request.method == 'POST':

        if user_config_form.validate_on_submit():
            # Test current passwd    
            if not current_user_from_db.check_password(user_config_form.user_current_password.data):
                flash('Invalid current password', 'error')
                return redirect(url_for('user_config'))
            else:
                current_user_from_db.user_name = user_config_form.user_name.data
                current_user_from_db.user_email = user_config_form.user_email.data
                if user_config_form.new_password.data and user_config_form.new_password2.data:
                    current_user_from_db.set_password(user_config_form.new_password.data)
                db.session.commit()

            flash('%s - changes done. Log in with new credentials' % user_config_form.user_name.data, 'success')
            return redirect(url_for('logout'))
        else:
            flash("%s - error %s'" % (user_config_form.user_name.data , user_config_form.errors), 'error')

    return render_template('user_config_form.html', title='user config', user_config_form=user_config_form)

@app.route('/logout')
@login_required
def logout():
    # Stop mega-cmd-server
    accs = Config.query.all()
    if accs:
        for acc in accs:
            kill_sessions(acc.id)
    kill_mega_cmd_server()
    logout_user()
    return redirect(url_for('login'))

# The info shown here is filtered by current_user.id
@app.route('/home')
@login_required
def home():
    num_accounts = Config.query.filter_by(user_id = current_user.id).count()

    if num_accounts == 0:
        flash('You do not have any mega account. Add one or upload a config file.', 'warning')
        return redirect(url_for('add_account'))

    # Global info
    acc_total = Config.query.filter_by(user_id = current_user.id).count()

    # Calcule updated accounts
    total_accounts_updated = 0
    user_accounts = Config.query.filter_by(user_id = current_user.id).all()

    for account in user_accounts:
        try:
            account_file_stats = FileStats.query.filter_by(config_id=account.id).first()
        except:
            account_file_stats = False

        if account_file_stats:
            if account_file_stats.local:
                remote_state = db.session.query(StateHash.is_update).filter_by(config_id = account_file_stats.config_id, file_type = 'remote').scalar()
                local_state = db.session.query(StateHash.is_update).filter_by(config_id = account_file_stats.config_id, file_type = 'local').scalar()
                if remote_state and local_state:
                    total_accounts_updated = int(total_accounts_updated) + 1
            else:
                remote_state = db.session.query(StateHash.is_update).filter_by(config_id = account_file_stats.config_id, file_type = 'remote').scalar()
                if remote_state:
                    total_accounts_updated = int(total_accounts_updated) + 1

    # @TODO: Calcule synced accounts
    acc_synced = 0

    space_total_bytes = db.session.query(db.func.sum(DiskStats.total_bytes)).filter_by(user_id = current_user.id).scalar()
    space_total_free_bytes = db.session.query(db.func.sum(DiskStats.free_bytes)).filter_by(user_id = current_user.id).scalar()
    space_total_used_bytes = db.session.query(db.func.sum(DiskStats.used_bytes)).filter_by(user_id = current_user.id).scalar()

    if space_total_bytes:
        space_total = humanfriendly.format_size(space_total_bytes, binary=True)
        space_total_free = humanfriendly.format_size(space_total_free_bytes, binary=True)
        space_total_used = humanfriendly.format_size(space_total_used_bytes, binary=True)
    else:
        space_total = humanfriendly.format_size(0, binary=True)
        space_total_free = humanfriendly.format_size(0, binary=True)
        space_total_used = humanfriendly.format_size(0, binary=True)

    # Config variables
    accounts = Config.query.filter_by(user_id = current_user.id).all()

    return render_template('home.html', title = 'home', os = os, Config=Config, DiskStats=DiskStats, FileStats=FileStats,StateHash=StateHash,
                           accounts=accounts, acc_total = acc_total, total_accounts_updated =  total_accounts_updated, 
                           acc_synced = acc_synced, space_total = space_total, space_total_free = space_total_free,
                           space_total_used = space_total_used)

@app.route('/add_account', methods=['GET', 'POST'])
@login_required
def add_account():
    account_form = AddAccountForm()
    upload_form = UploadConfigForm()

    if request.method == 'POST':
        # Account form
        if account_form.validate_on_submit():
            new_account = Config(
                user_id = current_user.id,
                name = account_form.name.data, 
                email = account_form.email.data, 
                passwd = account_form.passwd.data,
                local_dir = account_form.local_dir.data,
                local_links = account_form.local_links.data,
                remote_dir = account_form.remote_dir.data
                )
            db.session.add(new_account)

            # Get login parameters from db session
            acc = Config.query.filter_by(name = account_form.name.data).first()

            # Try update if not delete config data and do not insert disk data
            update_disk_try = get_disk_data(acc.id)

            if update_disk_try == 1:
                added="no"
                db.session.expunge(new_account)
                db.session.delete(acc)
                db.session.commit()
                flash('%s - has not been added' % (acc.name), 'error')
            else:
                db.session.commit()
                added="yes"

                # get remote_files
                get_remote_files(acc.id)

                # get local files
                get_local_files(acc.id)

                # update stats
                update_file_stats(acc.id)

                flash('%s - has been correctly added' % (acc.name), 'success')

            return render_template('add_account_confirm.html', title = 'add account confirm', added=added,
                                   name = acc.name, email = acc.email, passwd = acc.passwd, local_dir = acc.local_dir,
                                   remote_dir = acc.remote_dir)

        if upload_form.validate_on_submit():
            # check if the post request has the file part
            if 'file' not in request.files:
                flash('No file found', 'error')
                return redirect(request.url)

            file = request.files['file']

            if file and allowed_config_file(file.filename):
                filename = secure_filename(upload_form.file.data.filename)

                # Create tmp dir
                tmp_dir = tempfile.mkdtemp()

                upload_form.file.data.save(os.path.join(tmp_dir, filename))

                # @TODO get files without headers
                dataset = tablib.Dataset()

                # Read uploaded file
                with open(os.path.join(tmp_dir, filename)) as f:
                    # @TODO first line are headers
                    dataset.csv = f.read()

                # Delete tmp dir
                shutil.rmtree(tmp_dir)

                # Insert data in db
                for row in dataset:
                    try:
                        new_account = Config(user_id = current_user.id, name = row[0], email = row[1], passwd = row[2], local_dir = row[3], remote_dir = row[4])
                        db.session.add(new_account)
                    except:
                        pass

                # Declare result_list
                result_list = []

                for new_acc in db.session.new:
                    # Get login parameters from db session
                    acc = Config.query.filter_by(name = new_acc.name).first()

                    if not acc:
                        flash("Error reading config file line",'error')
                        continue

                    # Try update if not delete config data and do not insert disk data
                    update_disk_try = get_disk_data(acc.id)

                    if update_disk_try == 1:
                        added="no"
                        result_list.append([ acc.name, acc.email, acc.passwd, acc.local_dir, acc.remote_dir, added])

                        # Delete config data if account can't connect
                        Config.query.filter_by(name=acc.name).delete()
                        db.session.commit()
                        flash('%s - has not been added' % (acc.name), 'error')

                    else:
                        added="yes"
                        result_list.append([ acc.name, acc.email, acc.passwd, acc.local_dir, acc.remote_dir, added])

                        # get remote_files
                        get_remote_files(acc.id)

                        # get local files
                        get_local_files(acc.id)

                        # update stats
                        update_file_stats(acc.id)

                        flash('%s - has been correctly added' % (acc.name), 'success')

                return render_template('uploaded_config_file.html', title = 'uploaded config file', result_list = result_list)
            else:
                flash('File type not allowed.\n Allowed extensions: %s' % ", ".join([str(ext) for ext in CONFIG_ALLOWED_EXTENSIONS]), 'warning')
                return redirect(request.url)

    return render_template('add_account_form.html', account_form = account_form, upload_form = upload_form, title = 'add account')

@app.route('/config/<id>', methods=['GET', 'POST'])
@login_required
def config(id):
    config_form = ConfigForm()

    # get account params
    current_config = Config.query.filter_by(id=id).first()

    if request.method == 'GET':
        config_form.name.data = current_config.name
        config_form.email.data = current_config.email
        config_form.local_dir.data = current_config.local_dir
        config_form.local_links.data = current_config.local_links
        config_form.remote_dir.data = current_config.remote_dir

    if request.method == 'POST' and config_form.validate():
        # Modif
        if config_form.validate_on_submit():
            # Change current_config
            current_config.name = config_form.name.data
            current_config.email = config_form.email.data
            if config_form.passwd.data:
                current_config.passwd = config_form.passwd.data
            current_config.local_dir = config_form.local_dir.data
            current_config.local_links = config_form.local_links.data
            current_config.remote_dir = config_form.remote_dir.data

            db.session.commit()
            flash('Account config updated', 'success')

    return render_template('config_form.html', title = 'config',  config_form = config_form, current_config = current_config)
    
@app.route('/delete/<id>', methods=['GET', 'POST'])
@login_required
def delete(id):
    delete_account_form = DeleteAccountForm()

    # get account params
    current_config = Config.query.filter_by(id=id).first()
    name = current_config.name

    if request.method == 'GET':
        delete_account_form.name.data = current_config.name
        delete_account_form.email.data = current_config.email
        delete_account_form.passwd.data = 'Enter password again'
        delete_account_form.local_dir.data = current_config.local_dir
        delete_account_form.remote_dir.data = current_config.remote_dir

    if request.method == 'POST':
        # Delete account
        if delete_account_form.validate_on_submit():
            Config.query.filter_by(id=current_config.id).delete()  # Delete config
            DiskStats.query.filter_by(config_id=current_config.id).delete()  # Delete disk data
            Files.query.filter_by(config_id=current_config.id).delete()  # Delete files (remote, local, to_up, to_down)
            StateHash.query.filter_by(config_id=current_config.id).delete()  # Delete state hash (remote, local)
            FileStats.query.filter_by(config_id=current_config.id).delete()  # Delete file stats row
            db.session.commit()
            flash('%s - has been deleted' % name, 'success')
            return redirect('/home')

    return render_template('delete_form.html', title = 'delete', delete_account_form = delete_account_form)

@app.route('/files/<id>', methods=['GET', 'POST'])
@login_required
def files(id):
    # Get account info
    config = Config.query.filter_by(id=id).first()
    disk_stats = DiskStats.query.filter_by(config_id=config.id).first()
    file_stats = FileStats.query.filter_by(config_id=config.id).first()

    # Get files info
    remote_files = Files.query.filter_by(config_id=config.id, is_dir=False, file_type='remote').order_by(Files.filename.asc()).all()   
    local_files = Files.query.filter_by(config_id=config.id, is_dir=False, file_type='local' ).order_by(Files.filename.asc()).all()   

    # Show files
    return render_template('files.html', title = 'files', config = config,
                           disk_stats = disk_stats, file_stats = file_stats,
                           remote_files = remote_files, local_files = local_files)

@app.route('/files_details/<id>', methods=['GET', 'POST'])
@login_required
def files_details(id):
    # Get account info
    config = Config.query.filter_by(id=id).first()
    disk_stats = DiskStats.query.filter_by(config_id=config.id).first()
    file_stats = FileStats.query.filter_by(config_id=config.id).first()

    # Get files info
    remote_files = Files.query.filter_by(config_id=config.id, is_dir=False, file_type='remote').order_by(Files.filename.asc()).all()   
    local_files = Files.query.filter_by(config_id=config.id, is_dir=False, file_type='local' ).order_by(Files.filename.asc()).all()   

    # Show files
    return render_template('files_details.html', title = 'files details', config = config,
                           disk_stats = disk_stats, file_stats = file_stats,
                           remote_files = remote_files, local_files = local_files)

@app.route('/delete_remote_file/<file_id>', methods=['GET'])
@login_required
def delete_remote_file(file_id):
    remote_file = Files.query.filter_by(id = file_id).one() # Get file info
    acc = Config.query.filter_by(id = remote_file.config_id ).one() # Get accounts params

    # Instanciate accountmega handler and delete
    accmega = AccountMega(acc.id, acc.name, acc.email, acc.passwd)
    accmega.rm(remote_file.path.encode('utf-8'))

    # Set as not updated
    acc_state_hash = StateHash.query.filter_by(config_id= acc.id, file_type = 'remote').one()
    acc_state_hash.state_hash = 'changed'
    acc_state_hash.is_update = False
    db.session.commit()

    flash('%s - file %s has been delete from remote directory.' % (acc.name, unicode(remote_file.filename)), 'success')
    flash('%s - you should update this account' % acc.name, 'warning')
    return redirect('/files/%s' % acc.id)

@app.route('/copy/<file_id>',methods=['GET', 'POST'])
@login_required
def copy_file(file_id):
    copy_form = CopyForm()
    remote_file = Files.query.filter_by(id = file_id).one() # Get file info
    config = Config.query.filter_by(id = remote_file.config_id).one()

    user_accounts = Config.query.filter(Config.user_id == current_user.id, Config.id != config.id).all()
    user_accounts_list = [(i.id, i.name) for i in user_accounts]
    copy_form.acc_dst.choices = user_accounts_list

    if request.method == 'GET':
        copy_form.file_to_move.data = remote_file.path

    if request.method == 'POST' and copy_form.validate_on_submit():
        # Get dst params
        config_acc_dst = Config.query.filter_by(id = copy_form.acc_dst.data).one()
        dst_dir = copy_form.remote_dir_dst.data

        # Log out/in using megacmd
        os.system('mega-logout')
        passwd = '\'' + config_acc_dst.passwd + '\''
        os.system('mega-login %s %s' % (config_acc_dst.email, passwd))

        # Adapt remote path to megacmd
        if dst_dir == '/Root':
            dst_dir = '/'
        else:
            dst_dir = '/' + dst_dir.lstrip('/Root')

        # Test if remote dst dir exists before import
        command = 'mega-ls %s' % dst_dir
        test_dir = 0

        try:
            subprocess.check_call(command, stdout=FNULL, stderr=subprocess.STDOUT, shell=True)
        except:
            test_dir = 1

        if test_dir != 0:
            flash('%s - destination dir %s not found' % (config_acc_dst.name, dst_dir), 'error')
            kill_sessions(config_acc_dst.id)
            kill_mega_cmd_server()
            return redirect('/files/%s' % config.id)

        command = "mega-import '%s' '%s'" % (remote_file.link, dst_dir)
        result = subprocess.Popen(command, stdout=subprocess.PIPE, shell=True)
        output, err = result.communicate()

        if err:
            flash("%s - error importing file '%s' - %s"  % (config_acc_dst.name, remote_file.filename, err), 'error')
            subprocess.call('mega-logout')
            kill_sessions(config_acc_dst.id)
            kill_mega_cmd_server()
            return redirect('/files/%s' % config.id)
        elif output.split(':')[0] != 'Import file complete':
            time.sleep(5) # wait
        else:
            # Log out destination account
            kill_sessions(config_acc_dst.id)
            kill_mega_cmd_server()

            # Set as not updated
            acc_state_hash = StateHash.query.filter_by(config_id = config_acc_dst.id, file_type = 'remote').one()
            acc_state_hash.state_hash = 'changed'
            acc_state_hash.is_update = False
            db.session.commit()

            flash("%s - '%s'" % (config_acc_dst.name, output ), 'success')
            flash('%s - you should update this account' % config_acc_dst.name, 'warning')

            # Delete file in the source account if move option is checked
            move_checked = copy_form.move_check.data

            if move_checked:
                # Login in source account
                passwd = '\'' + config.passwd + '\''
                os.system('mega-login %s %s' % (config.email, passwd))

                # Delete
                command = "mega-rm '%s'" % remote_file.path.lstrip('/Root')
                result = subprocess.Popen(command, stdout=subprocess.PIPE, shell=True)
                output, err = result.communicate()

                if err:
                    flash("%s - error deleting file '%s' - %s"  % (config.name, remote_file.filename, err), 'error')
                    kill_sessions(config.id)
                    kill_mega_cmd_server()
                    return redirect('/files/%s' % config.id)
                else:
                    # Log out sourceaccount
                    kill_sessions(config.id)
                    os.system('mega-logout')
                    kill_mega_cmd_server()

                    # Set as not updated
                    acc_state_hash = StateHash.query.filter_by(config_id = config.id, file_type = 'remote').one()
                    acc_state_hash.state_hash = 'changed'
                    acc_state_hash.is_update = False
                    db.session.commit()

                    flash('%s - file %s deleted' % (config.name, remote_file.filename ), 'success')
                    flash('%s - you should update this account' % config.name, 'warning')
                    return redirect('/files/%s' % config.id)

    return render_template('copy.html', title = 'move', copy_form = copy_form )

@app.route('/webdav/<file_id>',methods=['GET'])
@login_required
def webdav_file(file_id):
     # Get file info
    remote_file = Files.query.filter_by(id = file_id).one()
    if not remote_file:
        flash('file not found. id %s' % file_id,'error')
        return redirect('/webdav/results')

    config = Config.query.filter_by(id = remote_file.config_id).one()

    if request.method == 'GET':
        # Test logged account
        command = 'mega-whoami'
        os.system(command)
        result = subprocess.Popen(command, stdout=subprocess.PIPE, shell=True)
        output, err = result.communicate()

        output_lines = output.splitlines()
        for line in output_lines:
            words = line.split()
            if 'Initiating' in words:
                continue
            elif 'Not' and 'logged' in words:
                # loggin with megacmd
                passwd = '\'' + config.passwd + '\''
                command = 'mega-login %s %s' % (config.email, passwd)
                os.system(command)
                command = 'mega-whoami'
                result = subprocess.Popen(command, stdout=subprocess.PIPE, shell=True)
                output, err = result.communicate()
                logged_email = output.split(':')[1].split()[0]
            else:
                logged_email = output.split(':')[1].split()[0]

            # Test if is new file belong to the same account
            if config.email != unicode(logged_email):
                logged_acc = db.session.query(Config).filter_by(email = logged_email).one()
                flash('%s - already serving files for account %s. Remove all served files and try again.' % (config.name, logged_acc.name ), 'error')
                return redirect('/webdav/results')
            else:
                # Serve file
                remote_file_path = '/' + remote_file.path.lstrip('/Root')  # Adapt remote path to megacmd
                command = "mega-webdav '%s' --port=5001 --public" % remote_file_path
                os.system(command)
                time.sleep(2)
                flash("%s - serving via webdav - '%s'" % (config.name, remote_file.filename),'success')
                return redirect('/webdav/results')

    return redirect('/webdav/results')

@app.route('/webdav/results',methods=['GET'])
@login_required
def webdav_results():
    user = User.query.filter_by(id = current_user.id).one()
    accs = Config.query.filter_by(user_id = current_user.id).all()
    logged_acc = False
    served_files = []
    num_served_files = 0
    webdav_output = False

    # Test logged account
    command = 'mega-whoami'
    os.system(command)
    result = subprocess.Popen(command, stdout=subprocess.PIPE, shell=True)
    output, err = result.communicate()

    accs_list = []
    for acc in accs:
        accs_list.append(acc.email)

    if output:
        output_lines = output.splitlines()
        for line in output_lines:
            words = line.split()
            if 'Initiating' in words:
                print "Initiating server..."
                continue
            elif 'Not' and 'logged' in words:
                served_files = False
                flash('%s - No logged in any account' % user.user_name, 'warning')
            else:
                logged_email = output.split(':')[1].split()[0]
                logged_acc = db.session.query(Config).filter_by(email = logged_email).one()
                command = 'mega-webdav'
                reload(sys)
                sys.setdefaultencoding('utf8')
                result = subprocess.Popen(command, stdout=subprocess.PIPE, shell=True)
                webdav_output, err = result.communicate()
    else:
        flash('Error getting logged account', 'error')

    if webdav_output:
        if webdav_output == 'Webdav server might not running. Add a new location to serve.\n':
            pass
        else:
            local_ip = get_ip()
            webdav_lines = webdav_output.splitlines()[1:]

            for line in webdav_lines:
                num_served_files += 1
                filepath_served = line.split(':')[0]
                filename = os.path.basename(filepath_served)

                # Get file info
                adapted_remote_path =  os.path.join('/Root' + filepath_served)
                remote_file = db.session.query(Files).filter_by(path = adapted_remote_path, file_type = 'remote').one()

                # Change IP to local IP
                webdav_link = line.split()[-1]
                raw_link = urlparse(webdav_link)
                webdav_local_link = raw_link.scheme + '://' + local_ip + ':' + str(raw_link.port) + raw_link.path

                # Save data into the list
                served_files.append((remote_file.id, filename, webdav_local_link))

        if num_served_files == 0:
            kill_sessions(logged_acc.id)  # logout too

    return render_template('webdav_results.html', title = 'webdav', logged_acc = logged_acc, num_served_files = num_served_files, served_files = served_files)

@app.route('/webdav/unset_all/<config_id>',methods=['GET'])
@login_required
def webdav_unset_all(config_id):
    acc =  Config.query.filter_by(id = config_id).one()
    command = 'mega-webdav -d --all'
    os.system(command)
    kill_sessions(config_id)  # logout too
    kill_mega_cmd_server()
    flash('%s - All files have been unset' % acc.name,'success')
    return redirect('/home')

@app.route('/webdav/unset/<file_id>',methods=['GET'])
@login_required
def webdav_unset(file_id):
    remote_file = db.session.query(Files).filter_by(id = file_id).one()
    acc = db.session.query(Config).filter_by(id = remote_file.config_id).one()
    remote_file_path = '/' + remote_file.path.lstrip('/Root')  # Adapt remote path to megacmd
    command = "mega-webdav -d '%s'" % remote_file_path
    os.system(command)
    flash('%s - file %s has been unset' % (acc.name, remote_file.filename),'success')
    return redirect('/webdav/results')

@app.route('/update/<id>', methods=['GET'])
@login_required
def update(id):
    config = Config.query.filter_by(id=id).one()

    #Thread(target=task_update, args=(app, config.id)).start()
    get_remote_files(config.id)
    get_local_files(config.id)
    update_file_stats(config.id)
    update_disk_data(config.id)

    flash('%s - has been updated' % config.name, 'success')
    return redirect('/home')

@app.route('/upload/<id>', methods=['GET', 'POST'])
@login_required
def upload(id):
    upload_file_form = UploadFileForm()
    config = Config.query.filter_by(id=id).one()
    remote_state_hash = StateHash.query.filter_by(config_id=config.id, file_type = 'remote').one()

    if request.method == 'GET':
        upload_file_form.remote_dir_dst.data = config.remote_dir

    if request.method == 'POST' and upload_file_form.validate_on_submit():

        # check if the post request has the file part
        if 'file' not in request.files:
            flash('No file found', 'error')
            return redirect(request.url)

        file = request.files['file']
        filename = secure_filename(upload_file_form.file.data.filename)
        #filename = upload_file_form.file.data.filename

        # Create tmp dir and save file
        tmp_dir = tempfile.mkdtemp()
        upload_file_form.file.data.save(os.path.join(tmp_dir, filename))
        _set_task_progress(50)

        # Instanciate accountmega handler
        accmega = AccountMega(config.id, config.name, config.email, config.passwd)

        # Upload from tmp dir
        if accmega.ls(upload_file_form.remote_dir_dst.data):
            accmega.put(os.path.join(tmp_dir, filename), os.path.join(upload_file_form.remote_dir_dst.data, filename))
            _set_task_progress(100)

            # Set State Hash to non updated
            remote_state_hash.state_hash = 'changed'
            remote_state_hash.is_update = False
            db.session.commit()

            flash('%s - file uploaded (%s)' % (config.name, filename), 'success') 
            flash('%s - you should update this account' % config.name, 'warning')
        else:
            _set_task_progress(100)
            flash('%s - remote target directory does not exists (%s)' % (config.name, upload_file_form.remote_dir_dst.data), 'error')
        # Delete tmp dir
        shutil.rmtree(tmp_dir)

    return render_template('upload.html', title = 'upload', upload_file_form = upload_file_form )

@app.route('/sync/<id>', methods=['GET'])
@login_required
def sync(id):
    config = Config.query.filter_by(id=id).first()
    remote_state_hash = StateHash.query.filter_by(config_id=config.id, file_type = 'remote').one()

    if not config.local_dir:
        flash('%s - no local dir' % config.name, 'error')
        return redirect('/home')
    elif config.local_dir:
        # logout before (in case of crash)
        os.system('mega-logout')

        passwd = '\'' + config.passwd + '\''
        os.system('mega-login %s %s' % (config.email, passwd))

        if config.remote_dir == '/Root':
            remote_dir = '/'
        else:
            remote_dir = '/' + config.remote_dir.lstrip('/Root')

        command = "mega-sync '%s' '%s'" % (config.local_dir, remote_dir)
        os.system(command)
        time.sleep(5) # Give room to mega-sync to create the proccess, it starts as synced.

        while subprocess.check_output('mega-sync').splitlines()[1].split()[4] != 'Synced':
            time.sleep(5)
        else:
            subprocess.call('mega-logout')
            kill_mega_cmd_server()

        # Setas non updated
        remote_state_hash.state_hash = 'changed'
        remote_state_hash.is_update = False
        db.session.commit()

        flash('%s - is synced. You have to update the account' % config.name, 'success')
        flash('%s - you should update this account' % config.name, 'warning')
        return redirect('/home')
    else:
        flash('%s - error while syncing' % config.name, 'error')
        return redirect('/home')

@app.route('/search', methods=['GET', 'POST'])
@login_required
def search():
    search_form = SearchForm()

    user_accounts = Config.query.filter_by(user_id = current_user.id) 
    user_accounts_list = [(i.id, i.name) for i in user_accounts]
    search_form.accounts.choices = user_accounts_list
    search_form.accounts.choices.insert(0, (0 , 'all'))

    if request.method == 'POST' and search_form.validate_on_submit():
        query = search_form.string_to_search.data
        accounts = search_form.accounts.data
        search_type = search_form.places.data

        return redirect((url_for('search_results', query = query, accounts = accounts, search_type = search_type)))

    return render_template('search_form.html', title = 'search', search_form = search_form)

@app.route('/search_results/<query>/<accounts>/<search_type>')
@login_required
def search_results(query, accounts, search_type):
    # all accounts
    if accounts == '0':
        if search_type == 'remote_search':
            results = Files.query.filter_by(user_id=current_user.id, is_dir=False, file_type='remote').filter(Files.filename.ilike('%{}%'.format(query)))
        elif search_type == 'local_search':
            results = Files.query.filter_by(user_id=current_user.id, is_dir=False, file_type='local').filter(Files.filename.ilike('%{}%'.format(query)))
        else:
            results = Files.query.filter_by(user_id=current_user.id, is_dir=False).filter(Files.filename.ilike('%{}%'.format(query)))
    # one account
    else:
        if search_type == 'remote_search':
            results = Files.query.filter_by(user_id=current_user.id, is_dir=False, file_type='remote', config_id = accounts).filter(Files.filename.ilike('%{}%'.format(query)))
        elif search_type == 'local_search':
            results = Files.query.filter_by(user_id=current_user.id, is_dir=False, file_type='local', config_id = accounts).filter(Files.filename.ilike('%{}%'.format(query)))
        else:
            results = Files.query.filter_by(user_id=current_user.id, is_dir=False, config_id = accounts).filter(Files.filename.ilike('%{}%'.format(query)))

    return render_template('search_results.html', title = 'search results', Config=Config, query=query, accounts=accounts, search_type=search_type, results=results)

@app.route('/search_results_details/<query>/<accounts>/<search_type>')
@login_required
def search_results_details(query, accounts, search_type):
    # all accounts
    if accounts == '0':
        if search_type == 'remote_search':
            results = Files.query.filter_by(user_id=current_user.id, is_dir=False, file_type='remote').filter(Files.filename.ilike('%{}%'.format(query)))
        elif search_type == 'local_search':
            results = Files.query.filter_by(user_id=current_user.id, is_dir=False, file_type='local').filter(Files.filename.ilike('%{}%'.format(query)))
        else:
            results = Files.query.filter_by(user_id=current_user.id, is_dir=False).filter(Files.filename.ilike('%{}%'.format(query)))
    # one account
    else:
        if search_type == 'remote_search':
            results = Files.query.filter_by(user_id=current_user.id, is_dir=False, file_type='remote', config_id = accounts).filter(Files.filename.ilike('%{}%'.format(query)))
        elif search_type == 'local_search':
            results = Files.query.filter_by(user_id=current_user.id, is_dir=False, file_type='local', config_id = accounts).filter(Files.filename.ilike('%{}%'.format(query)))
        else:
            results = Files.query.filter_by(user_id=current_user.id, is_dir=False, config_id = accounts).filter(Files.filename.ilike('%{}%'.format(query)))

    return render_template('search_results_details.html', title = 'search results', Config=Config, query=query, accounts=accounts, search_type=search_type, results=results)

@app.route('/automation', methods=['POST','GET'])
@login_required
def automation():
    form = AutomationForm()
    cron = CronTab(user=True)

    installed_jobs = cron.find_command('cron_update.py %s' % current_user.id)
    inst_job = []

    # Create job list    
    for job in installed_jobs:
        inst_job.append(job)

    if request.method == 'POST':
        if form.validate_on_submit():
            # Delete current cron jobs
            for item in inst_job:
                cron.remove( item )
                cron.write()
                print "Deleted crontab %s for user %s" %(item, current_user.id)

            # Create job
            path = os.getcwd()
            #python_path = os.path.join(path,'venv/bin/python') # For virtualenv
            python_path = 'python'
            job = cron.new(command='cd %s && %s %s/cron_update.py %s' % (path, python_path, path, current_user.id))

            # Get form data
            cron_option = form.cron_options.data

            if cron_option == 'never':
                flash('cron job %s set' %cron_option, 'success')
            elif cron_option == 'every_hour':
                job.set_comment('update mega accounts every HOUR for user %s [managed by mmega app]' % current_user.id)
                job.every().hours()
                job.enable()
                cron.write()
                flash('cron job %s set' %cron_option, 'success')
            elif cron_option == 'every_day':
                job.set_comment('update mega accounts every DAY for user %s [managed by mmega app]' % current_user.id)
                job.every().dom()
                job.enable()
                cron.write()
                flash('cron job %s set' %cron_option, 'success')
            elif cron_option == 'every_week':
                job.set_comment('update mega accounts every WEEK for user %s [managed by mmega app]' % current_user.id)
                job.dow.on('SUN')
                job.enable()
                cron.write()
            elif cron_option == 'every_month':
                job.set_comment('update mega accounts every MONTH for user %s [managed by mmega app]' % current_user.id)
                job.every().month()
                job.enable()
                cron.write()
                flash('cron job %s set' %cron_option, 'success')
            elif cron_option == 'every_year':
                job.set_comment('update mega accounts every YEAR for user %s [managed by mmega app]' % current_user.id)
                job.every().year()
                job.enable()
                cron.write()
                flash('cron job %s set' %cron_option, 'success')
            else:
                flash('cron job %s has not been set' %cron_option, 'error')

            return redirect((url_for('automation')))

    return render_template('automation_form.html', form=form, inst_job = inst_job)

