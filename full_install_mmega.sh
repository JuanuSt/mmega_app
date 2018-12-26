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

# Install system packages
  sudo -S apt update && sudo apt -y upgrade
  sudo apt -y install git
  sudo apt -y install wget
  sudo apt -y install redis-server
  sudo apt -y install megatools
  sudo apt -y install python-pip
  wget -q https://mega.nz/linux/MEGAsync/xUbuntu_18.04/amd64/megacmd-xUbuntu_18.04_amd64.deb
  sudo apt -y install -f ./megacmd-xUbuntu_18.04_amd64.deb
  rm megacmd-xUbuntu_16.08_amd64.deb

# Download app
  ssh-keyscan -H bitbucket.org >> ~/.ssh/known_hosts

  git clone https://juanust@bitbucket.org/juanust/mmega_app.git -b master

# Install python requeriments
  cd mmega_app
  pip install -r requeriments.txt

# Modify and copy mmega.service
  python_bin="$(which python)"
  mmega_path="$(echo $PWD)"
  sed -i s+EnvironmentFile=.*+EnvironmentFile="$mmega_path/service_env"+ mmega.service
  sed -i s+WorkingDirectory=.*+WorkingDirectory="$mmega_path"+ mmega.service
  sed -i s+User=.*+User="$USER"+ mmega.service
  sed -i s+ExecStart=.*+ExecStart="$python_bin $mmega_path/mmega.py"+ mmega.service
  sudo cp mmega.service /etc/systemd/system/mmega.service

# Delete files
  rm -r images
  rm install_dependencies.sh
  rm full_install_mmega.sh
  rm mmega.service
  rm requeriments.txt
  rm README.md
  rm .gitignore

echo
echo "Done"
echo
echo "execute:    python mmega.py"
echo "as service: sudo systemctl start mmega"
echo

exit
