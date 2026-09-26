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
#
# TWO INDEPENDENT VERDICTS go on the wire, and keeping them independent is the
# point of the publish block below:
#   status         - did the BUILD produce a signed .ipa (success/failed/canceled)
#   publish_status - not_attempted | success | failed, the upload to the
#                    tenant's App Store Connect
# plus publish_error_code (a machine token, never prose) and, for the duplicate
# build-number rejection, previous_build_number. A build whose .ipa exists is
# reported success even when publishing failed, so the tenant keeps the artifact
# their minutes paid for and is separately told publishing did not go through.
#
# NOTHING TENANT-FACING IS WORDED HERE. Every user-visible sentence is composed
# by the backend from these codes. The tenant must not learn which CI service
# builds their app and must not see build-machine paths, so no CI name, no CI
# identifier and no slice of CI or Apple output may be put into a field the
# backend renders (``error`` is one of those fields).
set -uo pipefail
# No -e: a callback failure must never fail the build; we just report the state.

: "${CM_ARTIFACT_LINKS:=}"
: "${CM_BUILD_STATUS:=}"
: "${CM_BUILD_ID:=}"
# none | tf_internal | testflight. Sent by the backend so this script can tell a
# build-only run from one that also uploads. Defaulted so an older backend that
# does not send it keeps the previous behaviour instead of crashing under -u.
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
  # STATUS is now purely "did the build produce a signed .ipa". A publish
  # failure used to be folded in here, and that cost the user the artifact
  # their minutes had already paid for: the ARTIFACT_FILENAME block below only
  # runs for a successful status, so a failed upload meant the backend never
  # got the secure name and never downloaded the .ipa. The publish verdict now
  # travels in its own field instead (see the block after this one).
  STATUS="success"
elif [ "${CM_BUILD_STATUS:-}" = "canceled" ] || [ "${CM_BUILD_STATUS:-}" = "cancelled" ]; then
  STATUS="canceled"
fi
echo "-> Resolved STATUS = '$STATUS' (publish_target=${REVS_PUBLISH_TARGET})"

# ---------------------------------------------------------------------------
# PUBLISH OUTCOME - a SECOND verdict, resolved independently of the build one.
#
# On a publish workflow the .ipa is uploaded AFTER the build steps, by the CI's
# own ``publishing.app_store_connect`` block, so "an .ipa exists" and "the
# tenant's app reached App Store Connect" are two different facts. They used to
# be collapsed into a single status, and both publish failures seen on real
# builds were shown to the tenant as a plain success.
#
# WHAT LEAVES THIS BLOCK IS A CODE, NEVER PROSE, and never a slice of the dump
# we read. That dump carries an "Authorization: Bearer <App Store Connect JWT>"
# which can create and revoke certificates in the tenant's Apple account for its
# validity window, and it is full of the CI's name and of /Users/... build paths
# that the tenant must never see. Exactly two allow-listed scalars leave here: a
# token from a fixed set and a run of digits.
#
# WHAT IS KNOWABLE HERE, AND WHAT IS NOT:
#
#  * The UPLOAD is synchronous, inside this run and before post-publish scripts
#    (CM_ARTIFACT_LINKS, which only exists once publishing has completed, is
#    populated by the time we read it). Its rejection is therefore observable:
#    we cannot read the publisher's exit code (it is not our script), so
#    detection is by CONTENT - codemagic-cli-tools, which the publisher is built
#    on, dumps the failed Apple request and response into a file under the
#    system temp dir (see scripts/sign.sh, which pins TMPDIR for the same
#    reason).
#
#  * The TestFlight BETA REVIEW SUBMISSION is NOT observable here at all. The CI
#    documents submit_to_testflight, expire_build_submitted_for_review,
#    beta_groups and release notes as being carried out asynchronously in a
#    post-processing step that starts after the workflow has finished, with no
#    status reported back to the build. That is exactly the second production
#    failure we saw ("App is missing required Beta App Review Information"): it
#    happens minutes later, on Apple's side, after this machine is gone. Only
#    the backend can learn it, by asking App Store Connect. Hence
#    publish_status=success means UPLOADED, not "distributed to testers", and
#    the backend words it that way for the external target. The internal target
#    (tf_internal) has no submission step, so for it "uploaded" is the whole
#    story - which is the main reason it exists.
# ---------------------------------------------------------------------------
PUBLISH_STATUS="not_attempted"
PUBLISH_ERROR_CODE=""
PREVIOUS_BUILD_NUMBER=""
# Guarded by STATUS too, not just by the target: with no .ipa there was nothing
# to upload, so a build failure must not also invent a publish failure for the
# same cause. "not attempted" is the honest answer there.
if [ "${REVS_PUBLISH_TARGET}" != "none" ] && [ "$STATUS" = "success" ]; then
  PUBLISH_STATUS="success"
  PUBLISH_SCAN=$(python3 - <<'PY' 2>/dev/null || true
import os
import re
import stat
import time

# Separator class absorbs backslashes so a re-escaped copy of Apple's answer
# (\"previousBundleVersion\": \"13\") matches as well as the plain one.
PREV = re.compile(r'previousBundleVersion["\\\s:]{1,8}(\d{1,12})')

MAX_FILES = 4000          # bounded walk: this runs on every publish build
MAX_BYTES = 4 * 1024 * 1024
MAX_DEPTH = 5
# Wall-clock budget for the whole walk. This runs in publishing.scripts, where
# a hang holds the build machine (billed) until max_build_duration and the
# backend never hears the verdict (seen 2026-09-26: 17+ minutes here).
MAX_SECONDS = 60


def classify(text):
    """Map a dump to (code, number). Content only; nothing from it is echoed.

    Ordered most specific first. An unrecognised dump returns None so the
    caller degrades to the generic code rather than to raw text.
    """
    # Apple HTTP 409. The pointer attribute is what narrows the generic
    # duplicate code to the build NUMBER: a duplicate version STRING reports
    # the same code on another pointer, and mislabelling it would send the
    # user to edit the wrong field.
    if ("ENTITY_ERROR.ATTRIBUTE.INVALID.DUPLICATE" in text
            and "cfBundleVersion" in text):
        m = PREV.search(text)
        # The number only; never the file, its path or any other field.
        return "appstore_build_number_duplicate", (m.group(1) if m else "")
    # Apple's long-standing delivery error when no app record exists for this
    # Bundle ID. The README calls that record a precondition, so the case is
    # real; the phrase is distinctive enough that a false positive is not a
    # practical concern. Unlike the duplicate above, this one has not yet been
    # seen on a build of ours - it fails closed (no match -> generic code).
    if "No suitable application records were found" in text:
        return "appstore_app_record_missing", ""
    return None


def scan():
    roots = []
    for d in (os.environ.get("TMPDIR") or "", "/tmp", "/var/folders"):
        if d and os.path.isdir(d) and d not in roots:
            roots.append(d)
    seen = 0
    deadline = time.monotonic() + MAX_SECONDS
    for root in roots:
        base = root.rstrip("/").count("/")
        for dirpath, dirnames, filenames in os.walk(root, onerror=lambda e: None):
            if dirpath.count("/") - base >= MAX_DEPTH:
                dirnames[:] = []
                continue
            for name in filenames:
                seen += 1
                if seen > MAX_FILES or time.monotonic() > deadline:
                    return None
                path = os.path.join(dirpath, name)
                try:
                    # Regular files only. open() on a FIFO blocks until a
                    # writer appears, and the temp dirs of a build machine do
                    # hold named pipes; sockets and devices are never dumps.
                    st = os.lstat(path)
                    if not stat.S_ISREG(st.st_mode) or st.st_size > MAX_BYTES:
                        continue
                    # O_NONBLOCK as well: if the path is swapped for a FIFO
                    # between lstat and open, the open still returns at once.
                    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0))
                    with os.fdopen(fd, "rb") as fh:
                        blob = fh.read(MAX_BYTES)
                except OSError:
                    continue
                hit = classify(blob.decode("utf-8", "ignore"))
                if hit is not None:
                    return hit
    return None


found = scan()
if found is not None:
    print("%s %s" % found)
PY
)
  PUBLISH_ERROR_CODE=$(printf '%s' "${PUBLISH_SCAN:-}" | awk '{print $1}')
  PREVIOUS_BUILD_NUMBER=$(printf '%s' "${PUBLISH_SCAN:-}" | awk '{print $2}')
  # Re-validate on this side too: the payload below is built from these two
  # variables, and only a token from this fixed set / bare digits may ever
  # reach a field the backend turns into text for the user.
  case "$PUBLISH_ERROR_CODE" in
    appstore_build_number_duplicate|appstore_app_record_missing) ;;
    *) PUBLISH_ERROR_CODE=""; PREVIOUS_BUILD_NUMBER="" ;;
  esac
  if ! printf '%s' "$PREVIOUS_BUILD_NUMBER" | grep -qE '^[0-9]{1,12}$'; then
    PREVIOUS_BUILD_NUMBER=""
  fi

  if [ -z "$PUBLISH_ERROR_CODE" ]; then
    # No dump named the rejection. Fall back to the run's own verdict: an
    # EXPLICIT failure on a run that DID produce an .ipa has passed every build
    # step, so the publishing section is what is left to have failed. Weaker
    # than the dump (the CI can fail a run for unrelated reasons in that
    # section), which is why it may only move THIS verdict: the .ipa is
    # delivered either way and the backend's generic message says so.
    case "${CM_BUILD_STATUS:-}" in
      failed|failure|error) PUBLISH_ERROR_CODE="appstore_publish_failed" ;;
    esac
  fi
  if [ -n "$PUBLISH_ERROR_CODE" ]; then
    PUBLISH_STATUS="failed"
  fi
fi
echo "-> PUBLISH_STATUS = '$PUBLISH_STATUS' code='${PUBLISH_ERROR_CODE:-<none>}' prev='${PREVIOUS_BUILD_NUMBER:-<none>}'"

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
  # The backend writes payload["error"] into custom_builds.error verbatim and
  # renders it to the user, so this line must stay STATIC and free of anything
  # that identifies the build environment. The CI provider's name and its build
  # id were both in it before, which is precisely what must not be shown, and no
  # value from the environment may be interpolated either. $STATUS is one of our
  # own three tokens. The actionable Russian text comes from the codes, not here.
  #
  # The old "Build succeeded but App Store Connect publishing failed" branch is
  # gone with it: that case is no longer a build failure at all, it is
  # STATUS=success plus publish_status=failed.
  ERROR_MSG="Build $STATUS"
fi

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
          PUBLISH_STATUS="$PUBLISH_STATUS" \
          PUBLISH_ERROR_CODE="$PUBLISH_ERROR_CODE" \
          PREVIOUS_BUILD_NUMBER="$PREVIOUS_BUILD_NUMBER" \
          PUBLISH_TARGET="$REVS_PUBLISH_TARGET" \
          CERT_ID="$CERT_ID" \
          CERT_EXPIRES_AT="$CERT_EXPIRES_AT" \
          CM_BUILD_ID="${CM_BUILD_ID:-}" \
          python3 - <<'PY'
import json, os, re
out = {
    "build_id": int(os.environ["REVS_BUILD_ID"]),
    "status": os.environ["STATUS"],
    # SUPERADMIN-ONLY, and it must stay that way: this URL names the CI
    # provider in its host. Anything that copies it into a user-visible field
    # re-introduces the leak this script exists to prevent.
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
# ``error_code`` now means the BUILD/SIGNING code and nothing else - the publish
# codes have their own key below, because a publish failure no longer implies a
# failed build and the two must be renderable side by side.
if os.environ["STATUS"] != "success" and os.environ.get("SIGN_ERROR_CODE"):
    out["error_code"] = os.environ["SIGN_ERROR_CODE"]

# The publish verdict, independent of ``status``. Always sent, including
# "not_attempted", so the backend can tell "we did not publish" from "an older
# runner that did not report publishing at all" (the key is simply absent then)
# and never has to guess from the target alone.
out["publish_status"] = os.environ["PUBLISH_STATUS"]
if os.environ.get("PUBLISH_ERROR_CODE"):
    out["publish_error_code"] = os.environ["PUBLISH_ERROR_CODE"]
    if os.environ.get("PREVIOUS_BUILD_NUMBER"):
        out["previous_build_number"] = os.environ["PREVIOUS_BUILD_NUMBER"]
# Echoed back so the backend can word "uploaded" correctly: for the external
# target an upload is only the start of Apple's review queue, for tf_internal it
# is the end of the road. This is OUR value, not the CI's, so it carries nothing
# about the build environment. Allow-listed anyway - it arrives as an env-var
# and ends up steering rendered text.
target = os.environ.get("PUBLISH_TARGET") or ""
if re.fullmatch(r"[a-z_]{1,20}", target):
    out["publish_target"] = target
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

echo "-> Notifying $REVS_BACKEND_URL/api/custom/ios/webhook (build=$STATUS publish=$PUBLISH_STATUS)"
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
