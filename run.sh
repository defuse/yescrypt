#!/bin/bash

set -e

case "${TORUN}" in
    ruby)
        ./test-ruby.sh
        ;;
    php)
        ./test-php.sh
        ;;
esac
