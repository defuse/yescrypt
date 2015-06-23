#!/bin/bash

rvm use 1.8.7
./test-ruby.sh

rvm use 1.9.2
./test-ruby.sh

rvm use 1.9.3
./test-ruby.sh

rvm use 2.0.0
./test-ruby.sh

rvm use 2.1
./test-ruby.sh

rvm use 2.2
./test-ruby.sh

rvm use jruby-18mode
./test-ruby.sh

rvm use jruby-19mode
./test-ruby.sh

rvm use rbx-2
./test-ruby.sh
