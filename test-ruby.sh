#!/bin/bash

# Build the testing tool.
cd reference/yescrypt-v1/yescrypt/yescrypt-0.7.1/
make clean
make ref
./tester 'ruby ../../../../ruby/yescrypt_cli.rb'

if [ $? -ne 0 ]; then
    echo "FAIL."
    exit 1
fi

echo "All tests pass."
exit 0
