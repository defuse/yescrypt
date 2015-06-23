#!/bin/bash

set -e

# http://packages.ubuntu.com/search?keywords=php5

sudo apt-get update

sudo apt-get remove php5
sudo apt-get install php5=5.5.12+dfsg-2ubuntu4.4
./test-php.sh

sudo apt-get remove php5
sudo apt-get install php5=5.6.4+dfsg-4ubuntu6
./test-php.sh
