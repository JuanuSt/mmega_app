#!/home/odoo/mmega_app/mmega_app/venv/bin/python2.7

import os, tablib, subprocess, humanfriendly, tempfile, md5, hashlib, shutil, time
from datetime import datetime, date
from flask_sqlalchemy import SQLAlchemy

print "hola"

# Sqlalchemy
SQLALCHEMY_DATABASE_URI = 'sqlite:///mmega.db'
#SQLALCHEMY_DATABASE_URI = 'postgresql://user:passwd@localhost/mmega'
SQLALCHEMY_ECHO = True
SQLALCHEMY_TRACK_MODIFICATIONS = False


