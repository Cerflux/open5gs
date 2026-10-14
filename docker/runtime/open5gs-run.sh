#!/bin/bash
# Run one Open5GS daemon in the foreground. The daemon also writes stderr,
# which `docker compose logs` collects.
set -eu

if [ "$#" -lt 1 ]; then
    echo "usage: open5gs-run <open5gs-daemon> [args...]" >&2
    exit 1
fi

exec "$@"
