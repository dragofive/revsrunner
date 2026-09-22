#!/usr/bin/env bash
#
# sign.sh
#
# Resolve the tenant's iOS distribution certificate and the App Store
# provisioning profile through the App Store Connect API, and leave both where
# build.sh expects them (login keychain + ~/Library/MobileDevice/...).
#
# Inputs (all env-vars, set by the RevsApp backend in the POST /builds payload):
#   BUNDLE_ID                 - the tenant's bundle identifier
#   APP_STORE_CONNECT_*       - the tenant's .p8 trio; codemagic-cli-tools reads
#                               these by default, we never pass them explicitly
#   CERTIFICATE_PRIVATE_KEY   - the project's PERSISTENT RSA distribution key,
#                               generated once by the backend, stored Fernet-
#                               encrypted, and resent unchanged on every build
#
# WHY THE KEY IS PERSISTENT NOW. Apple binds a certificate to the public half of
# the key that signed its CSR. The previous version of this script ran
# "openssl genrsa" on every build, so no existing certificate could ever match
# the new key and app-store-connect minted another one each time. Those pile up
# against Apple's (undocumented, so never hardcoded here) per-team cap, and they
# are what made the profile request carry more than one certificate. Same key in
# means the same certificate back, so we mint at most once per project.
#
# WHY WE DRIVE THE API BY HAND instead of "app-store-connect fetch-signing-files".
# That action's _create_missing_profiles lists the team's certificates WITHOUT
# the private key and puts every one of them into the profile request. Apple
# documents that an App Store provisioning profile "contains a single
# distribution certificate" and answers a two-certificate request with an opaque
# HTTP 500 (the CLI then retries it three times, with no backoff, and fails).
# There is no flag to narrow that list, so the profile has to be created
# explicitly with exactly one certificate id. Persisting the key fixes the
# accumulation; explicit profile creation fixes the 500. Both are needed.
#
# AUTOPILOT WITHOUT REVOKE. This script NEVER calls
# "app-store-connect certificates delete", on either plane: the same file is
# deployed byte for byte in custom-ios-runner and in the constructor's
# ios-template, so do not reintroduce revocation in either copy. A tenant brings
# their own Apple account and may be signing with those certificates outside
# RevsApp; revoking is a one-way action on someone else's property.
# Deleting a provisioning PROFILE that we created ourselves is a different
# thing and is explained at the point where it happens.
#
# SECRET DISCIPLINE. Environment variables delivered through the Codemagic
# POST /builds call are NOT treated as secret by Codemagic and are NOT masked in
# build logs, so this script is the only protection for the private key:
# no "set -x", no echo of the value, and never on a command line (argv is
# readable by any process and gets printed by tracebacks). Every reference uses
# the documented "@env:NAME" form, which passes the variable NAME, not its value.
set -eu

# Neutralise the one flag this script sets for itself (REVS_JSON_A_STDIN, see the
# JSON helper below). It is meant to be armed only as a command prefix on the
# single call site that also supplies the pipe, and a command-prefix assignment
# cannot escape that command. What it CANNOT defend against on its own is an
# AMBIENT variable of the same name arriving from outside (a stray Codemagic
# build variable, a wrapper script, the POST /builds payload): that would arm the
# stdin path for helper calls that pipe nothing, which at best resolves nothing
# and at worst blocks until Codemagic's timeout kills the build. Unsetting it
# here means the flag can only ever come from the one line that sets it.
unset REVS_JSON_A_STDIN 2>/dev/null || true

# codemagic-cli-tools dumps the request and response of a failed Apple API call
# into a folder under the system temp dir. On macOS that is a random per-process
# /var/folders/... path, so pin it to /tmp: the CLI prints the dump's path on
# failure and a predictable path makes that line actionable. TMPDIR is also
# where this script writes its own JSON helper below. Exporting it here only
# affects this step's own children.
#
# THAT DUMP IS DELIBERATELY NOT COLLECTED AS A BUILD ARTIFACT. It contains the
# full request, including the "Authorization: Bearer <App Store Connect JWT>"
# header, and that token can create and revoke certificates and profiles in the
# tenant's Apple account for its validity window. Codemagic retains artifacts,
# so publishing the dump would hand that token to anyone who can download a
# build. NEVER add a "signing-audit"-style glob to codemagic.yaml. The failure
# codes below plus the CLI's own stderr in the build log are the diagnostics.
export TMPDIR=/tmp

# The user never sees this log; they see custom_builds.error. So a failure hands
# a machine code to notify-backend.sh (which forwards it as error_code) and the
# backend turns it into a Russian sentence. Only the five codes the backend knows
# are emitted here: an unknown one silently degrades to the generic message.
SIGN_ERROR_FILE=/tmp/revs_sign_error
rm -f "$SIGN_ERROR_FILE"

# Companion to the file above, for the SUCCESS side: the Apple resource id of
# the certificate this build actually signed with, and its expiry date. Both are
# public facts about the tenant's own Apple account (the id is what they see in
# Certificates, Identifiers & Profiles), and neither can be derived from the
# private key, so writing them to a plain file is not a secret leak. The PRIVATE
# KEY never goes near this file, nor does anything derived from it.
# Two lines, in order: id, then expiry (RFC3339 as Apple returns it, or empty
# when the field could not be read). notify-backend.sh forwards them; a runner
# whose notify script does not know about this file simply ignores it, which is
# what the constructor's ios-template does.
SIGN_CERT_FILE=/tmp/revs_sign_cert
rm -f "$SIGN_CERT_FILE"

fail() {
  code="$1"
  shift
  printf '%s' "$code" > "$SIGN_ERROR_FILE" 2>/dev/null || true
  echo "::error::sign.sh: $*"
  exit 1
}

echo "===== sign.sh ====="

[ -n "${BUNDLE_ID:-}" ] || fail bundle_id_failed "BUNDLE_ID is not set"
# No fallback to generating a key here. A fallback would silently restore the
# behaviour this change removes, and it would do so precisely when the backend is
# misconfigured, i.e. when nobody is watching.
[ -n "${CERTIFICATE_PRIVATE_KEY:-}" ] || \
  fail signing_key_missing "CERTIFICATE_PRIVATE_KEY is not set (backend did not send the persistent signing key)"

keychain initialize

# ---------------------------------------------------------------------------
# JSON helper. Written to disk once rather than repeated as five heredocs, and
# used instead of grep/sed: the --json payloads are real JSON and mis-parsing one
# would mean signing with the wrong identity. Every mode prints the value asked
# for or nothing at all, and always exits 0, so "cannot tell" degrades to
# "nothing found" (mint / create) instead of crashing the build.
# ---------------------------------------------------------------------------
SIGN_PY="$TMPDIR/revs-sign-json.py"
cat > "$SIGN_PY" <<'PY'
import json
import os
import sys
from datetime import datetime, timedelta, timezone

# Do not sign with a certificate that dies mid-build or mid-TestFlight
# processing; re-mint on the last build before expiry instead.
EXPIRY_MARGIN_DAYS = 7

# Slot A may be STREAMED THROUGH STDIN instead of the environment, and only when
# the caller explicitly says so with REVS_JSON_A_STDIN=1 AND the mode asked for
# is the one mode that streams. WHY: on Unix the environment and argv share one
# ARG_MAX budget, so handing a large --json payload to this helper in an
# environment variable makes execve fail with E2BIG, which the shell reports as
# "Argument list too long" and this helper never even starts. A pipe has no such
# limit.
#
# WHY IT IS OPT-IN AND NEVER THE DEFAULT: a helper that read stdin by habit
# would block forever at a call site that left stdin attached to the terminal or
# to an idle pipe, and a hung build is far worse than a skipped cleanup. The flag
# names a single slot (A) because only one call site is large; slot B always
# keeps the environment form, so there is nothing to disambiguate.
#
# WHY THE MODE GATE ON TOP OF THE FLAG: sign.sh sets the flag as a command prefix
# on one pipeline, so nothing inside the script can leak it to the other modes,
# but an AMBIENT variable of that name would arm every mode at once. pick-cert
# would then read an empty (or worse, an idle) stdin instead of the certificate
# list, find no certificate while the Apple call itself succeeded, and fall
# through to the mint branch, creating a brand new distribution certificate on
# every build. That is exactly the accumulation defect the persistent key exists
# to remove, and this script is not allowed to undo it by revoking. Binding the
# flag to the mode that actually supplies the pipe makes that unreachable;
# together with the "unset" in sign.sh these are two independent guards.
_MODE = sys.argv[1] if len(sys.argv) > 1 else ""
STDIN_SLOT = "REVS_JSON_A" if (
    _MODE == "stale-profiles" and os.environ.get("REVS_JSON_A_STDIN") == "1"
) else ""

_stdin_cache = None


def _read_stdin():
    # Read once and remember it. The streaming mode asks for slot A only once
    # today, so this is defensive: a mode that walked the same slot twice (the
    # way pick-cert and cert-expiry walk A and then B) would otherwise get ""
    # from the second read of an already drained pipe and silently change the
    # answer.
    global _stdin_cache
    if _stdin_cache is None:
        try:
            # Decode the bytes here with errors="replace" rather than trusting
            # the process locale. The runner can come up under a C locale, where
            # text-mode stdin is ASCII, and one odd byte in some unrelated
            # profile's name would then raise and cost us the whole payload.
            # os.environ is lenient in the same way, so both slots behave alike.
            stream = getattr(sys.stdin, "buffer", None)
            if stream is not None:
                _stdin_cache = stream.read().decode("utf-8", "replace")
            else:
                _stdin_cache = sys.stdin.read()
        except Exception:
            _stdin_cache = ""
    return _stdin_cache


def resources(env_name):
    if env_name and env_name == STDIN_SLOT:
        raw = _read_stdin().strip()
    else:
        raw = (os.environ.get(env_name) or "").strip()
    if not raw:
        return []
    data = None
    try:
        data = json.loads(raw)
    except Exception:
        # Tolerate anything the CLI might print before the payload.
        for i, ch in enumerate(raw):
            if ch in "[{":
                try:
                    data, _ = json.JSONDecoder().raw_decode(raw[i:])
                except Exception:
                    data = None
                break
    if isinstance(data, dict):
        data = [data]
    if not isinstance(data, list):
        return []
    return [r for r in data if isinstance(r, dict)]


def attr(res, *names):
    attrs = res.get("attributes")
    if not isinstance(attrs, dict):
        attrs = {}
    for name in names:
        for src in (attrs, res):
            value = src.get(name)
            if isinstance(value, str) and value.strip():
                return value.strip()
    return ""


def rid(res):
    value = res.get("id")
    return value.strip() if isinstance(value, str) else ""


def parse_dt(text):
    if not text:
        return None
    t = text.replace("Z", "+00:00")
    if len(t) >= 5 and t[-5] in "+-" and t[-3] != ":":  # +0000 -> +00:00
        t = t[:-2] + ":" + t[-2:]
    try:
        return datetime.fromisoformat(t)
    except Exception:
        pass
    for fmt in ("%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S%z",
                "%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S"):
        try:
            return datetime.strptime(t, fmt)
        except Exception:
            continue
    return None


def pick_cert():
    # Newest certificate issued against our key, or nothing.
    seen = set()
    certs = []
    for env_name in ("REVS_JSON_A", "REVS_JSON_B"):
        for res in resources(env_name):
            cid = rid(res)
            if cid and cid not in seen:
                seen.add(cid)
                certs.append(res)
    if not certs:
        return ""
    sys.stderr.write(
        "-> %d certificate(s) issued against our key: %s\n"
        % (len(certs), ", ".join(sorted(seen)))
    )
    dated = []
    for res in certs:
        when = parse_dt(attr(res, "expirationDate", "expiration_date"))
        if when is None:
            continue
        if when.tzinfo is None:
            when = when.replace(tzinfo=timezone.utc)
        dated.append((when, rid(res)))
    if not dated:
        # Not one of them carried a readable expiry date, so the field name is
        # not what we expect. Dropping them all would mint a fresh certificate on
        # EVERY build, which is the exact defect this script exists to remove, so
        # reuse a deterministic, arbitrary one of them and say loudly that the
        # filter did nothing. Apple resource ids are opaque 10-character strings
        # with no relation to issue time, so sorting them says nothing about
        # recency; all this branch needs is that two concurrent builds of the
        # same project pick the SAME id.
        sys.stderr.write(
            "::warning::sign.sh: no readable expiration date on any certificate; "
            "the expiry filter is inactive, check the --json field names\n"
        )
        return sorted(seen)[-1]
    cutoff = datetime.now(timezone.utc) + timedelta(days=EXPIRY_MARGIN_DAYS)
    # Sorted by (expiry, id) and take the last, so two concurrent builds of the
    # same project converge on one certificate instead of each minting its own.
    usable = sorted((w, c) for w, c in dated if w > cutoff)
    if not usable:
        sys.stderr.write(
            "-> every matching certificate expires within %d days; re-minting\n"
            % EXPIRY_MARGIN_DAYS
        )
        return ""
    return usable[-1][1]


def cert_expiry():
    # Expiry date of ONE certificate, named by REVS_CERT_ID. Read out of the
    # payload we already have instead of a fresh "certificates get" call: an
    # extra Apple round trip on the happy path could fail and would then have to
    # be either ignored (pointless) or fatal (a build lost to a reporting
    # detail). Empty means "not reported", never "expired".
    want = (os.environ.get("REVS_CERT_ID") or "").strip()
    if not want:
        return ""
    for env_name in ("REVS_JSON_A", "REVS_JSON_B"):
        for res in resources(env_name):
            if rid(res) == want:
                return attr(res, "expirationDate", "expiration_date")
    return ""


def first_id():
    # Resource id out of a create response.
    for res in resources("REVS_JSON_A"):
        value = rid(res)
        if value:
            return value
    return ""


def pick_bundle_id():
    want = (os.environ.get("REVS_BUNDLE_ID") or "").strip()
    for res in resources("REVS_JSON_A"):
        if attr(res, "identifier") != want:
            continue
        # UNIVERSAL is a normal, buildable iOS bundle id, so it is accepted; only
        # a foreign platform is rejected. An absent platform is accepted too: the
        # identifier matched exactly, which is the stronger signal.
        platform = attr(res, "platform").upper()
        if platform and platform not in ("IOS", "UNIVERSAL"):
            continue
        value = rid(res)
        if value:
            return value
    return ""


def pick_profile():
    # "<id><TAB><STATE>" for the profile carrying our exact name, or nothing.
    want = os.environ.get("REVS_PROFILE_NAME") or ""
    for res in resources("REVS_JSON_A"):
        if attr(res, "name") != want:
            continue
        state = attr(res, "profileState", "profile_state").upper()
        if not state:
            sys.stderr.write(
                "::warning::sign.sh: profile state unreadable; treating the "
                "profile as stale and recreating it\n"
            )
        return rid(res) + "\t" + state
    return ""


def stale_profiles():
    # Our own dead profiles, left behind by earlier certificate rotations.
    prefix = os.environ.get("REVS_PROFILE_PREFIX") or ""
    current = os.environ.get("REVS_PROFILE_NAME") or ""
    if not prefix:
        return ""
    out = []
    for res in resources("REVS_JSON_A"):
        name = attr(res, "name")
        if not name.startswith(prefix) or name == current:
            continue
        # Positively dead only. An unreadable state must never lead to a delete.
        state = attr(res, "profileState", "profile_state").upper()
        if state not in ("INVALID", "EXPIRED"):
            continue
        value = rid(res)
        if value:
            out.append(value)
    return "\n".join(out)


MODES = {
    "pick-cert": pick_cert,
    "cert-expiry": cert_expiry,
    "first-id": first_id,
    "pick-bundle-id": pick_bundle_id,
    "pick-profile": pick_profile,
    "stale-profiles": stale_profiles,
}

mode = MODES.get(_MODE)
result = ""
if mode is not None:
    try:
        result = mode() or ""
    except Exception as exc:  # never crash the build on an unexpected shape
        sys.stderr.write("::warning::sign.sh: could not read the API response (%s)\n" % exc)
        result = ""
if result:
    print(result)
PY

# ---------------------------------------------------------------------------
# 1. The certificate. Look for one already issued against our key.
# ---------------------------------------------------------------------------
# The private key is a documented filter of "certificates list", which is how
# only OUR certificates come back and how the tenant's own ones stay untouched.
# Apple splits "Distribution" into the legacy generic type and the platform
# scoped one, and an existing certificate can be either flavour, so both are
# queried and the results are merged.
#
# The EXIT STATUS of both queries is kept, not discarded. "The team has no
# certificate for this key" and "we could not ask" look identical in the payload
# (both are empty), and treating the second one as the first is how a single
# Apple 5xx or socket timeout permanently burns a certificate slot we are never
# allowed to free again. Minting requires a positive, successful answer.
echo "-> Looking for a distribution certificate issued against our key"
CERT_LIST_RC=0
CERTS_IOS=$(app-store-connect certificates list \
  --type IOS_DISTRIBUTION \
  --certificate-key @env:CERTIFICATE_PRIVATE_KEY \
  --json) || CERT_LIST_RC=$?
CERTS_LEGACY=$(app-store-connect certificates list \
  --type DISTRIBUTION \
  --certificate-key @env:CERTIFICATE_PRIVATE_KEY \
  --json) || CERT_LIST_RC=$?

# EVERY non-streaming helper call gets "</dev/null". The helper reads stdin only
# when it is explicitly told to and only in the one streaming mode, so this is
# redundant today; it is here so that "this call can never block" holds without
# depending on the environment or on a future edit to the helper, and it costs
# nothing. The single streaming call site at the bottom of the script is the one
# place that keeps its stdin, because there it carries the payload.
CERT_ID=$(REVS_JSON_A="$CERTS_IOS" REVS_JSON_B="$CERTS_LEGACY" \
  python3 "$SIGN_PY" pick-cert </dev/null)

# Whichever payload described the certificate we end up using, so the expiry
# below is read from the same answer the choice was made on.
CERT_JSON_A=""
CERT_JSON_B=""

if [ -n "$CERT_ID" ]; then
  echo "-> Reusing certificate $CERT_ID"
  CERT_JSON_A="$CERTS_IOS"
  CERT_JSON_B="$CERTS_LEGACY"
elif [ "$CERT_LIST_RC" -ne 0 ]; then
  # A certificate minted as IOS_DISTRIBUTION does not reliably show up under the
  # legacy DISTRIBUTION filter either, so ONE failing call is enough to hide an
  # existing certificate. Stop instead of creating a second one.
  fail cert_create_failed \
    "could not list the team's distribution certificates (App Store Connect returned an error); refusing to mint a new one on an unread answer"
else
  # The only place a certificate is ever created. Under a stable team and an
  # intact stored key this runs once in the life of a project. No cap check and
  # no pruning: Apple does not publish the cap and we are not allowed to free a
  # slot by revoking, so a refusal is reported to the tenant instead.
  echo "-> No usable certificate for our key; creating one (IOS_DISTRIBUTION)"
  CERT_CREATED=$(app-store-connect certificates create \
    --type IOS_DISTRIBUTION \
    --certificate-key @env:CERTIFICATE_PRIVATE_KEY \
    --json) || fail cert_create_failed "app-store-connect certificates create failed"
  CERT_ID=$(REVS_JSON_A="$CERT_CREATED" python3 "$SIGN_PY" first-id </dev/null)
  [ -n "$CERT_ID" ] || fail cert_create_failed "certificates create returned no resource id"
  echo "-> Created certificate $CERT_ID"
  CERT_JSON_A="$CERT_CREATED"
fi

# Report the certificate back to the backend through notify-backend.sh. Best
# effort in every direction: an unreadable expiry date is reported as empty and
# a write failure is swallowed, because a build that produced a correctly signed
# .ipa must never be failed over a status line. Nothing here is a secret, see
# SIGN_CERT_FILE above.
CERT_EXPIRES_AT=$(REVS_JSON_A="$CERT_JSON_A" REVS_JSON_B="$CERT_JSON_B" \
  REVS_CERT_ID="$CERT_ID" python3 "$SIGN_PY" cert-expiry </dev/null)
printf '%s\n%s\n' "$CERT_ID" "$CERT_EXPIRES_AT" > "$SIGN_CERT_FILE" 2>/dev/null || true
echo "-> Certificate $CERT_ID expires ${CERT_EXPIRES_AT:-<unknown>}"

# Save exactly this one certificate as a .p12. "certificates list --save" would
# write one for EVERY match, and a second identity in the keychain is how
# codesign starts picking the wrong one. The default CERTIFICATES_DIRECTORY is
# already one of the default search paths of "keychain add-certificates", so
# neither side needs a path flag, and the .p12 never leaves this runner (the
# artifact globs only collect .ipa files and xcodebuild logs).
app-store-connect certificates get "$CERT_ID" \
  --certificate-key @env:CERTIFICATE_PRIVATE_KEY \
  --save >/dev/null || fail cert_create_failed "could not download certificate $CERT_ID"

# ---------------------------------------------------------------------------
# 2. The bundle id resource.
# ---------------------------------------------------------------------------
# --strict-match-identifier is required: without it "com.example.app" also
# matches the tenant's extensions ("com.example.app.share") and we could build a
# profile for the wrong resource. --platform is deliberately NOT passed: that
# filter is an exact match and would drop a UNIVERSAL bundle id, which is a
# perfectly normal iOS one. The platform is checked locally instead.
#
# As with the certificate above, the exit status is kept. This path is worse
# than the certificate one if it degrades to "create": Apple refuses a duplicate
# identifier, so creating one it already holds fails on EVERY build and the
# project is wedged for good rather than self-healing.
echo "-> Resolving bundle id $BUNDLE_ID"
BUNDLE_LIST_RC=0
BUNDLE_IDS=$(app-store-connect bundle-ids list \
  --bundle-id-identifier "$BUNDLE_ID" \
  --strict-match-identifier \
  --json) || BUNDLE_LIST_RC=$?
BUNDLE_ID_RESOURCE=$(REVS_JSON_A="$BUNDLE_IDS" REVS_BUNDLE_ID="$BUNDLE_ID" \
  python3 "$SIGN_PY" pick-bundle-id </dev/null)

if [ -z "$BUNDLE_ID_RESOURCE" ]; then
  if [ "$BUNDLE_LIST_RC" -ne 0 ]; then
    fail bundle_id_failed \
      "could not list bundle ids (App Store Connect returned an error); refusing to register $BUNDLE_ID on an unread answer"
  fi
  if [ -n "$BUNDLE_IDS" ]; then
    # The call succeeded and returned something we could not read, so "absent"
    # is a guess. Try create anyway, but keep a local-match fallback for the
    # likely case that Apple already holds the identifier.
    echo "::warning::sign.sh: bundle-ids list returned a shape we could not read; check the --json field names"
  fi
  echo "-> Not registered yet; creating it"
  BUNDLE_CREATED=$(app-store-connect bundle-ids create "$BUNDLE_ID" \
    --platform IOS \
    --json) || BUNDLE_CREATED=""
  if [ -n "$BUNDLE_CREATED" ]; then
    BUNDLE_ID_RESOURCE=$(REVS_JSON_A="$BUNDLE_CREATED" python3 "$SIGN_PY" first-id </dev/null)
  fi
  if [ -z "$BUNDLE_ID_RESOURCE" ]; then
    # Most likely cause of a failed create: the identifier exists and the strict
    # listing above is the thing we could not read. Re-list WITHOUT the strict
    # filter (a superset: it also returns the tenant's extensions) and match the
    # identifier exactly on our side, which pick-bundle-id already does.
    echo "-> create yielded no resource id; re-listing without the strict filter"
    BUNDLE_IDS_ALL=$(app-store-connect bundle-ids list \
      --bundle-id-identifier "$BUNDLE_ID" \
      --json || true)
    BUNDLE_ID_RESOURCE=$(REVS_JSON_A="$BUNDLE_IDS_ALL" REVS_BUNDLE_ID="$BUNDLE_ID" \
      python3 "$SIGN_PY" pick-bundle-id </dev/null)
  fi
  [ -n "$BUNDLE_ID_RESOURCE" ] || \
    fail bundle_id_failed "could not resolve or register bundle id $BUNDLE_ID"
fi
echo "-> Bundle id resource $BUNDLE_ID_RESOURCE"

# ---------------------------------------------------------------------------
# 3. The provisioning profile, built with EXACTLY ONE certificate.
# ---------------------------------------------------------------------------
# The certificate id is part of the name on purpose. Apple requires profile names
# to be unique within a team, and a profile is bound to the certificates it was
# created with. With a certificate-independent name, a re-mint would leave the
# old ACTIVE profile in place, the name check would say "reuse" and the build
# would fail at signing with a mismatched identity. With the id in the name,
# "was this profile built with the certificate we are about to sign with" is a
# string comparison. The bundle id is in the name because the profile is bundle
# scoped and a tenant who changes it must not collide with their own old profile.
PROFILE_PREFIX="RevsApp $BUNDLE_ID "
PROFILE_NAME="$PROFILE_PREFIX$CERT_ID"

PROFILES=$(app-store-connect profiles list \
  --type IOS_APP_STORE \
  --name "$PROFILE_NAME" \
  --json || true)
PROFILE_MATCH=$(REVS_JSON_A="$PROFILES" REVS_PROFILE_NAME="$PROFILE_NAME" \
  python3 "$SIGN_PY" pick-profile </dev/null)

PROFILE_ID=""
PROFILE_STATE=""
if [ -n "$PROFILE_MATCH" ]; then
  PROFILE_ID=$(printf '%s' "$PROFILE_MATCH" | cut -f1)
  PROFILE_STATE=$(printf '%s' "$PROFILE_MATCH" | cut -f2)
fi

if [ "$PROFILE_STATE" = "ACTIVE" ]; then
  # Steady state: no creation call at all, so no 500 is even possible here.
  # Re-listing with --save drops the .mobileprovision into PROFILES_DIRECTORY,
  # where "xcode-project use-profiles" in build.sh picks it up.
  echo "-> Reusing profile $PROFILE_NAME"
  app-store-connect profiles list \
    --type IOS_APP_STORE \
    --name "$PROFILE_NAME" \
    --save >/dev/null || fail profile_create_failed "could not download profile $PROFILE_NAME"
else
  if [ -n "$PROFILE_ID" ]; then
    # Apple refuses a second profile with a name already in use, so a profile of
    # ours that is no longer ACTIVE has to go or this project is wedged forever.
    # This is NOT a breach of the no-revoke policy: that policy protects the
    # tenant's CERTIFICATES, which are irreplaceable. A provisioning profile is
    # derived and regenerable in one call, and this one carries our own name and
    # our own certificate id. --ignore-not-found covers the race with a
    # concurrent build. No certificate is deleted anywhere in this script.
    echo "-> Profile $PROFILE_NAME is ${PROFILE_STATE:-<unknown>}; deleting it before recreating"
    app-store-connect profiles delete "$PROFILE_ID" --ignore-not-found </dev/null \
      || fail profile_stale "could not delete the stale profile $PROFILE_ID"
  fi
  # ONE certificate id. That single flag is the fix for the HTTP 500: Apple
  # documents that an App Store profile contains a single distribution
  # certificate, and fetch-signing-files sent every certificate of the team.
  echo "-> Creating profile $PROFILE_NAME with certificate $CERT_ID"
  app-store-connect profiles create "$BUNDLE_ID_RESOURCE" \
    --certificate-ids "$CERT_ID" \
    --type IOS_APP_STORE \
    --name "$PROFILE_NAME" \
    --save >/dev/null || fail profile_create_failed "could not create profile $PROFILE_NAME"
fi

# Best effort, never fatal: without this, every certificate rotation leaves a
# dead profile behind in the tenant's portal. Only names carrying our own
# "RevsApp <bundle> " prefix and a state Apple positively reports as INVALID or
# EXPIRED are touched; anything else, including anything we cannot read, is left
# alone. Called with "|| true", which also disables "set -e" inside the function.
#
# THIS IS THE ONE CALL SITE THAT STREAMS ITS PAYLOAD THROUGH STDIN. It asks for
# the team's ENTIRE App Store profile collection, which is unbounded and has
# already been observed at 100 records; pushing that through the environment blew
# the ARG_MAX budget that the environment shares with argv, the helper died with
# "Argument list too long", and the cleanup silently never ran. "printf" is a
# bash builtin, so the payload is not put on an argv either. Every OTHER call
# site above deliberately keeps the environment form: each of them passes one
# record or a handful (one certificate list per type, one create response, one
# bundle id, one profile looked up by exact name), they are nowhere near the
# limit, and an unnecessary pipe is one more way for a helper to end up waiting
# on input.
#
# THE PAGE SIZE IS NOT A PROBLEM HERE AND THERE IS NO FLAG FOR IT. Checked
# against the codemagic-cli-tools documentation and source: "profiles list"
# accepts only --type, --state, --name and --save (plus the generic auth, --json
# and logging options); there is no page-size and no all-pages flag to use. The
# library behind it already walks every page by itself, paginating with a
# per-request page size of 100 and no overall limit and following Apple's "next"
# link, so the "Found 100 Profiles" line in the build log is the COMPLETE set for
# this team and merely happens to equal the per-request page size. Narrowing the
# query with --state was considered and rejected: it takes a single state, so
# INVALID and EXPIRED would cost two extra Apple round trips for a payload that
# now costs nothing to pass. Even if a listing were ever truncated the cleanup
# stays correct and only becomes partial, because it deletes exclusively ids
# that carry our own prefix and that Apple positively reports as INVALID or
# EXPIRED; the next build picks up whatever was left.
cleanup_stale_profiles() {
  ALL_PROFILES=$(app-store-connect profiles list --type IOS_APP_STORE --json) || return 0
  STALE=$(printf '%s' "$ALL_PROFILES" | \
          REVS_JSON_A_STDIN=1 \
          REVS_PROFILE_PREFIX="$PROFILE_PREFIX" \
          REVS_PROFILE_NAME="$PROFILE_NAME" \
          python3 "$SIGN_PY" stale-profiles)
  [ -n "$STALE" ] || return 0
  # BOUNDED PER BUILD. This cleanup never actually executed before the streaming
  # fix (the helper died with E2BIG), so the first successful run may face the
  # whole backlog of the era when every build minted its own certificate and left
  # a profile behind. Each delete is a separate interpreter start, JWT and Apple
  # round trip, run serially, inside the signing step whose minutes are billed for
  # Custom Builds. Capping it keeps that time predictable; whatever is left over
  # is taken by the next build, and with the persistent key new dead profiles now
  # appear about once a year, so the backlog converges either way.
  CLEANUP_LIMIT=20
  CLEANUP_DONE=0
  CLEANUP_LEFT=0
  # Fed by a herestring rather than a pipe: a piped "while" runs in a subshell
  # and the two counters would not survive it. The delete keeps its own
  # "</dev/null" so it cannot swallow the loop's input.
  while IFS= read -r stale_id; do
    [ -n "$stale_id" ] || continue
    if [ "$CLEANUP_DONE" -ge "$CLEANUP_LIMIT" ]; then
      CLEANUP_LEFT=$((CLEANUP_LEFT + 1))
      continue
    fi
    echo "-> Removing our own dead profile $stale_id"
    app-store-connect profiles delete "$stale_id" --ignore-not-found </dev/null || true
    CLEANUP_DONE=$((CLEANUP_DONE + 1))
  done <<< "$STALE"
  if [ "$CLEANUP_LEFT" -gt 0 ]; then
    echo "-> Stopped after $CLEANUP_DONE deletions; $CLEANUP_LEFT more dead profile(s) left for the next build"
  fi
  return 0
}
cleanup_stale_profiles || true

# Import the saved .p12 into the build keychain. Last, as before: nothing between
# "certificates get --save" and here needs the identity, and keeping the import
# at the end keeps the step boundary with build.sh unchanged.
keychain add-certificates

echo "-> Signing files ready (certificate $CERT_ID, profile $PROFILE_NAME)"
echo "==================="
