#!/bin/bash

# This script will install mmega from repository

# Lock file
  lock_file=/tmp/full_install_mmega.lock
  if [ -f "$lock_file" ]; then
     echo "Script is already running"
     exit 1
  fi
  touch $lock_file

# Delete lock file at exit
  trap "rm -f $lock_file" EXIT

# Variables
  ssh_key=~/.ssh/id_ed25519

# Install system packages
  sudo apt update && sudo apt -y upgrade
  sudo apt-get -y install git
  sudo apt -y install megatools
  sudo apt -y install python-pip
  wget -q https://mega.nz/linux/MEGAsync/xUbuntu_16.04/amd64/megacmd-xUbuntu_16.04_amd64.deb
  sudo apt -y install -f ./megacmd-xUbuntu_16.04_amd64.deb
  rm megacmd-xUbuntu_16.04_amd64.deb
  #sudo apt -y install virtualenv

# Download app
  ssh-keyscan -H bitbucket.org >> ~/.ssh/known_hosts
  eval $(ssh-agent)
  ssh-add "$ssh_key"
  git clone git@bitbucket.org:juanust/mmega_app.git -b master

# Install python requeriments
  cd mmega_app
  pip install -r requeriments.txt


exit
