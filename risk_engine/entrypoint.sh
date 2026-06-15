#!/bin/bash
# Fix ownership of the shared_data volume mount before dropping to appuser.
# The named volume is initialised as root by Docker; this ensures appuser
# can create and write the SQLite database under /data.
set -e
mkdir -p /data
chown appuser:appgroup /data
exec gosu appuser "$@"
