# -*- coding: UTF-8 -*-

## Dev config ##

# Imports
import os

# Flask
DEBUG = True
ENV='dev'
#SERVER_NAME = ''

# Sqlalchemy
SQLALCHEMY_DATABASE_URI = 'sqlite:///mmega.db'
#SQLALCHEMY_DATABASE_URI = 'postgresql://user:passwd@localhost/mmega'
SQLALCHEMY_ECHO = True
SQLALCHEMY_TRACK_MODIFICATIONS = False

# Security
SECRET_KEY = os.environ.get('SECRET_KEY') or 'Cop1pmveT/r0gx0BQqRIR77VyoI='
        
