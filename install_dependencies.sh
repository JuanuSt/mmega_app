#!/bin/bash

# This script will install mmega dependences
# Run this script from mmega_app directory
# Uncomment the lines if you want to upgrade and install virtualenv

sudo apt update
#sudo apt -y upgrade
sudo apt -y install megatools
wget -q https://mega.nz/linux/MEGAsync/xUbuntu_16.04/amd64/megacmd-xUbuntu_16.04_amd64.deb
sudo apt -y install -f ./megacmd-xUbuntu_16.04_amd64.deb
rm megacmd-xUbuntu_16.04_amd64.deb
sudo apt -y install python-pip
#sudo apt -y install virtualenv
pip install -r requeriments.txt

exit
