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
# The backend looks the build up by REVS_BUILD_ID, so a replay cannot write into
# another build's row without that build's key.
set -uo pipefail
# No -e: a callback failure must never fail the build; we just report the state.

: "${CM_ARTIFACT_LINKS:=}"
: "${CM_BUILD_STATUS:=}"
: "${CM_BUILD_ID:=}"

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
elif [ "${CM_BUILD_STATUS:-}" = "canceled" ] || [ "${CM_BUILD_STATUS:-}" = "cancelled" ]; then
  STATUS="canceled"
fi
echo "-> Resolved STATUS = '$STATUS'"

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
  ERROR_MSG="Codemagic build $STATUS (build id ${CM_BUILD_ID:-unknown})"
fi

PAYLOAD=$(REVS_BUILD_ID="$REVS_BUILD_ID" \
          STATUS="$STATUS" \
          ARTIFACT_FILENAME="$ARTIFACT_FILENAME" \
          ERROR_MSG="$ERROR_MSG" \
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
