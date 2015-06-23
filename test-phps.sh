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

# NOTE: After looking at the output, the problem is that it's only 5.3 that's
# available in apt-get... have to figure out how it makes the other versions
# available when the language is PHP.
