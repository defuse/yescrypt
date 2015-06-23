#!/bin/bash

set -e

# http://packages.ubuntu.com/search?keywords=php5

sudo apt-get update

echo "AVAILABLE VERSIONS"
sudo apt-cache showpkg php5

echo "MADISON"
sudo apt-cache madison

sudo apt-get remove php5
sudo apt-get install php5=5.5\*
./test-php.sh

sudo apt-get remove php5
sudo apt-get install php5=5.6\*
./test-php.sh
