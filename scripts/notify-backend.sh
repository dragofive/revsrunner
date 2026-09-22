#!/usr/bin/env bash
#
# notify-backend.sh
#
# Report the final build outcome to the RevsApp custom-iOS webhook. Runs in the
# publishing block (post-build, always), so it must survive failures in earlier
# scripts - every input is defaulted before we hash and curl.
#
# Required env-vars (set by RevsApp at start_build):
#   REVS_BACKEND_URL    - origin of the backend (no trailing slash).
#   REVS_WEBHOOK_TOKEN  - per-build HMAC-SHA256 key (NOT the global secret).
#   REVS_BUILD_ID       - the CustomBuild row id we are reporting on.
#
# Posts to /api/custom/ios/webhook a JSON body HMAC-signed with REVS_WEBHOOK_TOKEN.
# On a failure it also forwards the machine code sign.sh left in
# /tmp/revs_sign_error as "error_code"; the backend turns the five known codes
# into a Russian sentence the tenant can act on (app/api/custom_ios_webhook.py).
# The backend looks the build up by REVS_BUILD_ID, so a replay cannot write into
# another build's row without that build's key.
set -uo pipefail
# No -e: a callback failure must never fail the build; we just report the state.

: "${CM_ARTIFACT_LINKS:=}"
: "${CM_BUILD_STATUS:=}"
: "${CM_BUILD_ID:=}"
: "${REVS_PUBLISH_TARGET:=none}"

if [ -z "${REVS_BACKEND_URL:-}" ] || \
   [ -z "${REVS_WEBHOOK_TOKEN:-}" ] || \
   [ -z "${REVS_BUILD_ID:-}" ]; then
  echo "::warning::REVS_* env-vars missing - skipping callback"
  exit 0
fi

echo "===== notify-backend.sh ====="
echo "CM_BUILD_STATUS = '${CM_BUILD_STATUS:-<unset>}'"
echo "CM_ARTIFACT_LINKS length=${#CM_ARTIFACT_LINKS}"

# Resolve status, most-trustworthy signal first:
#   1) a local .ipa under build/ios/ipa/  -> success (build.sh normalized it here)
#   2) an .ipa in CM_ARTIFACT_LINKS       -> success
#   3) canceled env                       -> canceled
#   4) otherwise                          -> failed
STATUS="failed"

LOCAL_IPA=""
if [ -d "build/ios/ipa" ]; then
  LOCAL_IPA=$(ls -1 build/ios/ipa/*.ipa 2>/dev/null | head -n 1 || true)
fi
echo "-> Local .ipa = '${LOCAL_IPA:-<not found>}'"

HAS_IPA=$(python3 - <<'PY' 2>/dev/null || echo ""
import json, os
raw = os.environ.get("CM_ARTIFACT_LINKS", "")
try:
    items = json.loads(raw) if raw else []
except Exception:
    items = []
if not isinstance(items, list):
    items = []
for it in items:
    if not isinstance(it, dict):
        continue
    name = (it.get("name") or it.get("filename") or "").lower()
    if name.endswith(".ipa") and (it.get("url") or it.get("publicUrl")):
        print("yes")
        break
PY
)

if [ -n "$LOCAL_IPA" ] || [ "$HAS_IPA" = "yes" ]; then
  STATUS="success"
  # For a publish build (TestFlight), a built .ipa is not the whole
  # story: the upload+submit runs in the publishing block AFTER the build. If
  # Codemagic's overall status is an EXPLICIT failure, the submission failed even
  # though the .ipa exists - report failed so the user is not told it shipped
  # when it did not. An empty/unknown status stays success (no false negatives).
  if [ "${REVS_PUBLISH_TARGET}" != "none" ]; then
    case "${CM_BUILD_STATUS:-}" in
      failed|failure|error) STATUS="failed" ;;
    esac
  fi
elif [ "${CM_BUILD_STATUS:-}" = "canceled" ] || [ "${CM_BUILD_STATUS:-}" = "cancelled" ]; then
  STATUS="canceled"
fi
echo "-> Resolved STATUS = '$STATUS' (publish_target=${REVS_PUBLISH_TARGET})"

# Mine the .ipa secure filename out of CM_ARTIFACT_LINKS (the URLs there need the
# Codemagic API token to download; the backend mints a real public URL itself).
ARTIFACT_FILENAME=""
if [ "$STATUS" = "success" ] && [ -n "${CM_ARTIFACT_LINKS:-}" ]; then
  ARTIFACT_FILENAME=$(python3 - <<'PY' 2>/dev/null || true
import json, os, re
raw = os.environ.get("CM_ARTIFACT_LINKS", "")
try:
    items = json.loads(raw) if raw else []
except Exception:
    items = []
if not isinstance(items, list):
    items = []
for it in items:
    if not isinstance(it, dict):
        continue
    name = (it.get("name") or it.get("filename") or "").lower()
    url = it.get("url") or it.get("publicUrl") or ""
    if not (name.endswith(".ipa") and url):
        continue
    m = re.search(r"/+artifacts/+(.+)$", url)
    print(m.group(1) if m else url)
    break
PY
)
fi
echo "-> ARTIFACT_FILENAME = '${ARTIFACT_FILENAME:-<none>}'"

ERROR_MSG=""
if [ "$STATUS" != "success" ]; then
  if [ "${REVS_PUBLISH_TARGET}" != "none" ] && [ -n "$LOCAL_IPA" ]; then
    # Built fine but the App Store Connect upload/submit failed.
    ERROR_MSG="Build succeeded but App Store Connect publishing failed (build id ${CM_BUILD_ID:-unknown})"
  else
    ERROR_MSG="Codemagic build $STATUS (build id ${CM_BUILD_ID:-unknown})"
  fi
fi
# ERROR_MSG must stay a STATIC string: the backend writes payload["error"] into
# custom_builds.error verbatim and renders it to the tenant, so interpolating a
# build value here would turn it into a user-visible echo.

# sign.sh writes a machine code for the signing failure it hit; the backend maps
# it to a Russian sentence the tenant can act on ("free a certificate slot",
# "check the Bundle ID"), which the generic English line above cannot do.
# Allow-listed to a bare token so a corrupt or truncated file can never inject
# prose into a field that is rendered to the user, and read with a default so a
# missing file (every successful build) is not an error under `set -u`.
SIGN_ERROR_CODE=$(cat /tmp/revs_sign_error 2>/dev/null || true)
SIGN_ERROR_CODE=$(printf '%s' "${SIGN_ERROR_CODE:-}" | tr -d '\r\n')
if ! printf '%s' "$SIGN_ERROR_CODE" | grep -qE '^[a-z_]{1,40}$'; then
  SIGN_ERROR_CODE=""
fi
echo "-> SIGN_ERROR_CODE = '${SIGN_ERROR_CODE:-<none>}'"

# sign.sh also leaves the Apple resource id of the certificate this build signed
# with and its expiry date in /tmp/revs_sign_cert (id on line 1, expiry on line
# 2). Forwarded so the backend can record WHICH certificate a given .ipa was
# signed by; the tenant-facing certificate panel is driven by the backend's own
# live App Store Connect query, so this is history, not the source of truth, and
# an absent file changes nothing.
#
# THE PRIVATE KEY IS NEVER PART OF THIS. Only the id and the date are read, both
# of which the tenant can already see in their own Apple account, and both are
# allow-listed below so a truncated or corrupt file can never inject prose into a
# field the backend stores. Defaults are set up-front for `set -u` on a build
# that failed before sign.sh ever ran.
CERT_ID=""
CERT_EXPIRES_AT=""
if [ -r /tmp/revs_sign_cert ]; then
  CERT_ID=$(sed -n '1p' /tmp/revs_sign_cert 2>/dev/null | tr -d '\r\n')
  CERT_EXPIRES_AT=$(sed -n '2p' /tmp/revs_sign_cert 2>/dev/null | tr -d '\r\n')
fi
# Apple resource ids are opaque short alphanumerics; anything else is dropped
# together with the date, since a date without a trustworthy id says nothing.
if ! printf '%s' "$CERT_ID" | grep -qE '^[A-Za-z0-9]{1,64}$'; then
  CERT_ID=""
  CERT_EXPIRES_AT=""
fi
# RFC3339 as Apple returns it ("2027-05-14T09:12:33.000+0000"). An unreadable
# date degrades to "not reported" rather than to a wrong date.
if ! printf '%s' "$CERT_EXPIRES_AT" | grep -qE '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:.+-]{1,24}Z?$'; then
  CERT_EXPIRES_AT=""
fi
echo "-> CERT_ID = '${CERT_ID:-<none>}' expires '${CERT_EXPIRES_AT:-<unknown>}'"

PAYLOAD=$(REVS_BUILD_ID="$REVS_BUILD_ID" \
          STATUS="$STATUS" \
          ARTIFACT_FILENAME="$ARTIFACT_FILENAME" \
          ERROR_MSG="$ERROR_MSG" \
          SIGN_ERROR_CODE="$SIGN_ERROR_CODE" \
          CERT_ID="$CERT_ID" \
          CERT_EXPIRES_AT="$CERT_EXPIRES_AT" \
          CM_BUILD_ID="${CM_BUILD_ID:-}" \
          python3 - <<'PY'
import json, os
out = {
    "build_id": int(os.environ["REVS_BUILD_ID"]),
    "status": os.environ["STATUS"],
    "log_url": (
        f"https://codemagic.io/app/builds/{os.environ['CM_BUILD_ID']}"
        if os.environ.get("CM_BUILD_ID") else None
    ),
}
if os.environ.get("ARTIFACT_FILENAME"):
    out["artifact_secure_filename"] = os.environ["ARTIFACT_FILENAME"]
if os.environ.get("ERROR_MSG"):
    out["error"] = os.environ["ERROR_MSG"]
# Only on a non-success report: a stale file from an earlier step must never
# decorate a build that actually produced an .ipa. The payload is HMAC-signed
# over the whole body, so an extra field needs no signature change, and the
# webhook ignores fields it does not know.
if os.environ["STATUS"] != "success" and os.environ.get("SIGN_ERROR_CODE"):
    out["error_code"] = os.environ["SIGN_ERROR_CODE"]
# Reported on ANY status, unlike error_code: a build that signed and then failed
# to compile still tells us which certificate exists in the tenant's Apple
# account. The body is HMAC-signed as a whole, so extra keys need no signature
# change, and the webhook reads the payload as a plain dict and ignores keys it
# does not know - an older backend is unaffected by these two.
if os.environ.get("CERT_ID"):
    out["cert_id"] = os.environ["CERT_ID"]
    if os.environ.get("CERT_EXPIRES_AT"):
        out["cert_expires_at"] = os.environ["CERT_EXPIRES_AT"]
print(json.dumps({k: v for k, v in out.items() if v is not None}))
PY
)

SIG=$(printf "%s" "$PAYLOAD" \
       | openssl dgst -sha256 -hmac "$REVS_WEBHOOK_TOKEN" \
       | sed 's/^.*= //')

echo "-> Notifying $REVS_BACKEND_URL/api/custom/ios/webhook ($STATUS)"
HTTP_CODE=$(curl -s -o /tmp/revs-webhook.out -w "%{http_code}" \
  --max-time 30 \
  -X POST "$REVS_BACKEND_URL/api/custom/ios/webhook" \
  -H "Content-Type: application/json" \
  -H "X-Revs-Signature: sha256=$SIG" \
  -d "$PAYLOAD" || echo "000")

echo "-> Backend responded with HTTP $HTTP_CODE"
if [ "$HTTP_CODE" != "200" ]; then
  echo "::warning::Webhook non-200; backend will fall back to the timeout sweeper"
  echo "Body: $(cat /tmp/revs-webhook.out 2>/dev/null || true)"
fi
echo "============================="
