#!/usr/bin/env bash
#
# sign.sh
#
# Fetch (or mint) the tenant's iOS distribution certificate + provisioning
# profile via the App Store Connect API, using the .p8 creds passed as env-vars
# (codemagic-cli-tools reads APP_STORE_CONNECT_* by default). No UI-uploaded
# certs required.
#
# AUTOPILOT WITHOUT REVOKE: unlike the constructor's ios-template, we do NOT
# revoke the user's existing distribution certificates - a Custom Builds user
# brings their OWN Apple account, which they may also sign with manually. We
# never touch their existing certs.
#
# Trade-off: Apple caps a team at 3 active distribution certs. Because each CI
# build mints a fresh key (no cross-build state), a user who builds repeatedly
# can hit that cap; fetch-signing-files then 409s and this step fails with a
# clear message. The user frees a slot in their Apple Developer account
# (Certificates -> revoke an unused one). A future slice can persist and reuse a
# single cert per project to avoid this entirely.
set -e

echo "===== sign.sh ====="
keychain initialize

# Apple issues a Distribution Certificate only against a CSR, and a CSR can only
# be produced by the side holding the private key (Apple never stores it). So we
# generate a fresh RSA key on this runner and pass it via --certificate-key.
openssl genrsa -out /tmp/dist_key.pem 2048

echo "-> Fetching / minting signing files for $BUNDLE_ID (no revoke)"
app-store-connect fetch-signing-files "$BUNDLE_ID" \
  --type IOS_APP_STORE \
  --certificate-key=@file:/tmp/dist_key.pem \
  --create

keychain add-certificates
echo "-> Signing files ready"
echo "==================="
