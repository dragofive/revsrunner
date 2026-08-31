#!/usr/bin/env bash
#
# download-source.sh
#
# Fetch the user's project ZIP from the presigned URL the backend put in
# REVS_SOURCE_URL and unpack it into ./src. The ZIP was already safe-extracted
# and validated on the backend at upload time (zip-slip / entry-count / size
# caps), and this runs on an ephemeral throwaway mac VM, so a plain unzip here is
# acceptable.
set -euo pipefail

echo "===== download-source.sh ====="
mkdir -p src

echo "-> Downloading source ZIP"
# -f: fail on HTTP error; -S: show error; -L: follow redirects; capped time.
curl -fSL --max-time 900 -o /tmp/source.zip "$REVS_SOURCE_URL"

SIZE=$(wc -c < /tmp/source.zip | tr -d ' ')
echo "-> Downloaded ${SIZE} bytes"

echo "-> Unpacking into ./src"
unzip -q -o /tmp/source.zip -d src
rm -f /tmp/source.zip

echo "-> Top of source tree:"
ls -la src | head -n 40 || true
echo "=============================="
