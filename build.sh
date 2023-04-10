#!/bin/bash

set -ex

sudo apt update
sudo apt install python3-pip python3.7
python3.7 -m pip install -r requirements.txt
