#!/bin/bash
set -e

# Clear stale pid file if exists
rm -f /var/run/cups/cupsd.pid /run/cups/cupsd.pid 2>/dev/null || true

# Start CUPS service if not already running
if ! lpstat -r >/dev/null 2>&1; then
    if command -v service >/dev/null 2>&1; then
        service cups start >/dev/null 2>&1 || cupsd &
    elif command -v cupsd >/dev/null 2>&1; then
        cupsd &
    fi
fi

exec "$@"

