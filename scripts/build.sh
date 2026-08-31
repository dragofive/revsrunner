#!/usr/bin/env bash
#
# build.sh
#
# Prebuild the user's project by type, discover its Xcode workspace/project +
# scheme, apply the provisioning profiles fetched in sign.sh, and produce a
# signed .ipa. Output is normalized into build/ios/ipa/ so the codemagic.yaml
# artifact glob and notify-backend.sh find it in one place.
set -euo pipefail

echo "===== build.sh ====="

# Project root inside the unpacked source. detect.py records the effective root
# (the folder it descended into if the ZIP nested everything one level down) in
# REVS_BUILD_CONFIG.root; default to the source root.
ROOT=$(python3 -c "import json,os; c=json.loads(os.environ.get('REVS_BUILD_CONFIG') or '{}'); print(c.get('root') or '.')" 2>/dev/null || echo ".")
cd "src/$ROOT"
echo "-> Project root: $(pwd)"

TYPE="${REVS_PROJECT_TYPE:-unknown}"
echo "-> Project type: $TYPE"

install_node_deps() {
  if [ -f yarn.lock ]; then
    yarn install --frozen-lockfile || yarn install
  elif [ -f pnpm-lock.yaml ]; then
    npx pnpm install || npm install
  else
    npm install
  fi
}

# --- Framework prebuild: leave a buildable ios/ Xcode project behind. ---------
case "$TYPE" in
  flutter)
    echo "-> flutter pub get"
    flutter pub get
    # Build without codesign here; we sign via the fetched profiles at build-ipa.
    echo "-> flutter build ios --release --no-codesign"
    flutter build ios --release --no-codesign
    IOS_DIR="ios"
    ;;
  react_native|expo)
    echo "-> installing node deps"
    install_node_deps
    if [ ! -d ios ]; then
      echo "-> no ios/ dir; running expo prebuild"
      npx expo prebuild -p ios --no-install
    fi
    IOS_DIR="ios"
    ;;
  capacitor)
    echo "-> installing node deps"
    install_node_deps
    # A BYO Capacitor project already ships ios/. Best-effort sync (the user is
    # responsible for having built their web assets / configured the project).
    npx cap sync ios || echo "-> cap sync skipped/failed (continuing)"
    IOS_DIR="ios"
    ;;
  ios|*)
    # Native project: ios/ may be a subfolder or the root itself.
    if [ -d ios ]; then IOS_DIR="ios"; else IOS_DIR="."; fi
    ;;
esac

echo "-> iOS dir: $IOS_DIR"

# --- CocoaPods (only if a Podfile is present). --------------------------------
if [ -f "$IOS_DIR/Podfile" ]; then
  echo "-> pod install in $IOS_DIR"
  ( cd "$IOS_DIR" && pod install )
elif [ -f Podfile ]; then
  echo "-> pod install in project root"
  pod install
  IOS_DIR="."
fi

# --- Discover the workspace (preferred) or project, then a scheme. ------------
WS=$(find "$IOS_DIR" -maxdepth 3 -name "*.xcworkspace" -not -path "*/.*" 2>/dev/null | head -n 1 || true)
PROJ=$(find "$IOS_DIR" -maxdepth 3 -name "*.xcodeproj" -not -path "*/.*" 2>/dev/null | head -n 1 || true)

if [ -n "$WS" ]; then
  CONTAINER_FLAG="--workspace"
  CONTAINER="$WS"
  LIST=$(xcodebuild -list -workspace "$WS" 2>/dev/null || true)
elif [ -n "$PROJ" ]; then
  CONTAINER_FLAG="--project"
  CONTAINER="$PROJ"
  LIST=$(xcodebuild -list -project "$PROJ" 2>/dev/null || true)
else
  echo "::error::No .xcworkspace or .xcodeproj found under $IOS_DIR"
  exit 1
fi

# Pick the first scheme listed under "Schemes:" from `xcodebuild -list`.
SCHEME=$(printf "%s\n" "$LIST" | awk '/Schemes:/{f=1;next} f&&NF{sub(/^[ \t]+/,"");print;exit}')
if [ -z "${SCHEME:-}" ]; then
  echo "::error::Could not determine an Xcode scheme"
  echo "$LIST"
  exit 1
fi
echo "-> Container: $CONTAINER"
echo "-> Scheme: $SCHEME"

# --- Apply profiles + build the signed ipa. -----------------------------------
xcode-project use-profiles
xcode-project build-ipa $CONTAINER_FLAG "$CONTAINER" --scheme "$SCHEME"

# --- Normalize the artifact into <clone-root>/build/ios/ipa/. -----------------
# We cd'd into src/$ROOT, but the codemagic.yaml artifact glob and
# notify-backend.sh look under the CLONE ROOT (CM_BUILD_DIR), so copy the .ipa
# there (an absolute path) rather than a path relative to the project root.
DEST_DIR="${CM_BUILD_DIR:-$(pwd)}/build/ios/ipa"
mkdir -p "$DEST_DIR"
IPA=$(find . -maxdepth 6 -name "*.ipa" -not -path "*/.*" 2>/dev/null | head -n 1 || true)
if [ -n "$IPA" ]; then
  cp -f "$IPA" "$DEST_DIR/$(basename "$IPA")"
  echo "-> Built ipa: $DEST_DIR/$(basename "$IPA")"
else
  echo "::error::build-ipa did not produce an .ipa"
  exit 1
fi
echo "==================="
