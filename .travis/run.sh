#!/bin/bash

set -e

case "${TORUN}" in
    ruby)
        echo "Running the Ruby tests..."
        ./test-ruby.sh
        ;;
    php)
        echo "Running the PHP tests..."
        ./test-php.sh
        ;;
    *)
        exit 1
        ;;
esac
