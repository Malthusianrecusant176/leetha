#!/bin/sh
# Ensure the data directory is writable by appuser.
# Docker named volumes mount as root — fix ownership on every start.
chown -R appuser:appuser /home/appuser/.leetha 2>/dev/null || true

exec su -s /bin/sh appuser -c "leetha $*"
