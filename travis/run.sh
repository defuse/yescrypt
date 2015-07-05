#!/bin/bash

set -e

case "${TORUN}" in
    ruby)
        echo "Running the Ruby tests..."
        ruby -v
        ./test-ruby.sh
        ;;
    php)
        echo "Running the PHP tests..."
        php -v
        ./test-php.sh
        ;;
    *)
        exit 1
        ;;
esac
