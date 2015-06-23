#!/bin/bash

set -e

apt-get remove php
apt-get install php5=5.5.12+dfsg-2ubuntu4.4
./test-php.sh

apt-get remove php
apt-get install php5=5.6.4+dfsg-4ubuntu6
./test-php.sh
