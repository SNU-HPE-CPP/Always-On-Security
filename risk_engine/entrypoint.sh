#!/bin/bash
# Fix ownership of the shared_data volume mount before dropping to appuser.
# The named volume is initialised as root by Docker; this ensures appuser
# can create and write the SQLite database under /data.
# FIX #12: Also create /data/forensics so the router can write pre-quarantine
# artefacts without a PermissionError at runtime.
set -e
mkdir -p /data /data/forensics /data/integrity_audits
chown -R appuser:appgroup /data
exec gosu appuser "$@"
