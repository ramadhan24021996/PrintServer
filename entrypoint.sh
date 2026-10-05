#!/bin/bash
set -e

# Start CUPS service if installed and not already running
if lpstat -r >/dev/null 2>&1; then
    echo "CUPS service is already active."
else
    if command -v service >/dev/null 2>&1; then
        service cups start >/dev/null 2>&1 || true
    elif command -v cupsd >/dev/null 2>&1; then
        cupsd &
    fi
fi

exec "$@"
