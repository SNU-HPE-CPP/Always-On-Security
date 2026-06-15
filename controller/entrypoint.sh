#!/bin/bash
# Fix ownership of the shared_data volume mount before dropping to appuser.
# The named volume is initialised as root by Docker; this ensures appuser
# can write the offset file and any other data files under /data.
set -e
mkdir -p /data
chown appuser:appgroup /data
exec gosu appuser "$@"
