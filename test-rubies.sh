#!/bin/bash

rvm 1.8.7 exec ./test-ruby.sh

rvm 1.9.2 exec ./test-ruby.sh

rvm 1.9.3 exec ./test-ruby.sh

rvm 2.0.0 exec ./test-ruby.sh

rvm 2.1 exec ./test-ruby.sh

rvm 2.2 exec ./test-ruby.sh

rvm jruby-18mode exec ./test-ruby.sh

rvm jruby-19mode exec ./test-ruby.sh

rvm rbx-2 exec ./test-ruby.sh
