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
  sudo apt -y install nginx
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

# Create mmega.service
  uwsgi_bin="$(find / -name uwsgi 2>/dev/null | grep bin)"
  sed -i s+User=.*+User="$USER"+ mmega.service
  sed -i s+WorkingDirectory=.*+WorkingDirectory="$PWD"+ mmega.service
  sed -i s+ExecStart=.*+ExecStart="$uwsgi_bin --ini $PWD/uwsgi.ini"+ mmega.service
  sudo cp mmega.service /etc/systemd/system/mmega.service

# Create uwsgi.ini
  sudo mkdir -p /var/log/uwsgi
  sudo chown -R $USER:$USER /var/log/uwsgi
  SECRET_KEY="$(tr -cd '[:alnum:]' < /dev/urandom | fold -w32 | head -n1)"
  sed -i s+app_folder=.*+app_folder="$PWD"+ uwsgi.ini
  sed -i s+user=.*+user="$USER"+ uwsgi.ini
  sed -i s+env=SECRET_KEY=.*+env=SECRET_KEY="$SECRET_KEY"+ uwsgi.ini

# Create nginx config
  sed -i s+root.*+root" $PWD"\;+ mmega_nginx.conf
  sed -i s+unix:.*+unix:"$PWD"/mmega.sock\;+ mmega_nginx.conf
  if [ -e /etc/nginx/sites-enabled/default ];then
     sudo rm /etc/nginx/sites-enabled/default
  fi
  sudo cp mmega_nginx.conf /etc/nginx/sites-available/mmega
  sudo ln -s /etc/nginx/sites-available/mmega /etc/nginx/sites-enabled/mmega
  sudo service nginx restart

# Delete files
  rm -r images
  rm install_dependencies.sh
  rm mmega_installer.sh
  rm mmega.service
  rm mmega_nginx.conf
  rm requeriments.txt
  rm README.md
  rm .gitignore

echo
echo "Success: mmega_app has been installed"
echo " - Now you can execute 'python mmega.py' to test the installation. Observe that you're using a dev environment config"
echo " - To start mmega as service execute 'sudo systemctl start mmega'. You must adapt the environment variable and change to prod config"
echo

exit
