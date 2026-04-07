#!/bin/sh
# Fix volume ownership if running as root (e.g., docker run --user root).
# When running as appuser (default), skip — capabilities are preserved.
if [ "$(id -u)" = "0" ]; then
    chown -R appuser:appuser /home/appuser/.leetha 2>/dev/null || true
fi

exec leetha "$@"
