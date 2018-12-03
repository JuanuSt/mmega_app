# -*- coding: UTF-8 -*-

## Prod config ##

# Imports
import os

# Flask
DEBUG = False
ENV='production'
#SERVER_NAME = ''

# Sqlalchemy
SQLALCHEMY_DATABASE_URI = 'sqlite:///mmega.db'
#SQLALCHEMY_DATABASE_URI = 'postgresql://user:passwd@localhost/mmega'
SQLALCHEMY_ECHO = False
SQLALCHEMY_TRACK_MODIFICATIONS = False

# Security
SECRET_KEY = os.environ.get('SECRET_KEY')
