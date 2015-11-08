#!/bin/bash

# Build the testing tool.
cd reference/yescrypt-0.8.1/yescrypt-0.8.1
make ref

./tester "node ../../../javascript/yescrypt-cli.js SIMD"

if [ $? -ne 0 ]; then
    echo "FAIL."
    exit 1
fi

echo "All tests pass."
exit 0
