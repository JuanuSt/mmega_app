#!/bin/bash

# This script will install mmega dependences
# Run this script from mmega_app directory
# Uncomment the lines if you want to upgrade and install virtualenv

# Install system packages
  sudo -S apt update
  #sudo apt -y upgrade
  sudo apt -y install ssh
  sudo apt -y install git
  sudo apt -y install wget
  sudo apt -y install nginx
  sudo apt -y install redis-server
  sudo apt -y install megatools
  sudo apt -y install python-pip
  wget -q https://mega.nz/linux/MEGAsync/xUbuntu_18.04/amd64/megacmd-xUbuntu_18.04_amd64.deb
  sudo apt -y install -f ./megacmd-xUbuntu_18.04_amd64.deb
  rm megacmd-xUbuntu_18.04_amd64.deb
  #sudo apt -y install virtualenv
  pip install -r requeriments.txt

exit
