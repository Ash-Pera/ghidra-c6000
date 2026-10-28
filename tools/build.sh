#!/usr/bin/env bash
#
# Build the C6000 Ghidra extension.
#
# This exists because `buildExtension` does NOT compile SLEIGH.  A zip built
# without compiled SLEIGH installs cleanly and then fails at import time with
# "Unsupported language".  This script compiles every .slaspec first, then
# builds, then verifies that the zip really contains the .sla files.
#
# Usage:
#   tools/build.sh [--install [GHIDRA_DIR]]
#
# Environment:
#   GHIDRA_INSTALL_DIR  Ghidra install root (default: Homebrew's opt/ghidra)
#   JAVA_HOME           JDK home (default: the version in Ghidra's application.java.min)
#   GHIDRA_WORK         scratch directory for user.home / Gradle caches
#                       archive-path.txt records the verified output zip
#   GRADLE_USER_HOME    optional shared Gradle cache (default: GHIDRA_WORK/gradle)
#
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="${GHIDRA_WORK:-$ROOT/scratch/build}"

die() { printf 'error: %s\n' "$*" >&2; exit 1; }
note() { printf '\n== %s\n' "$*"; }

case "${1:-}" in
  "") [ "$#" -eq 0 ] || die "usage: tools/build.sh [--install GHIDRA_DIR]" ;;
  --install) [ "$#" -le 2 ] || die "usage: tools/build.sh [--install GHIDRA_DIR]" ;;
  *) die "usage: tools/build.sh [--install GHIDRA_DIR]" ;;
esac

resolve_ghidra() {
  if [ -n "${GHIDRA_INSTALL_DIR:-}" ]; then printf '%s\n' "$GHIDRA_INSTALL_DIR"
  elif [ -x /opt/homebrew/opt/ghidra/libexec/support/analyzeHeadless ]; then
    printf '%s\n' /opt/homebrew/opt/ghidra/libexec
  else
    ls -d /opt/homebrew/Cellar/ghidra/*/libexec 2>/dev/null | sort -V | tail -1
  fi
}

resolve_java_home() {
  if [ -n "${JAVA_HOME:-}" ] && [ -x "$JAVA_HOME/bin/java" ]; then
    printf '%s\n' "$JAVA_HOME"; return
  fi
  for c in "/opt/homebrew/opt/openjdk@$1/libexec/openjdk.jdk/Contents/Home" \
           "/opt/homebrew/opt/openjdk@$1" \
           "/usr/lib/jvm/temurin-$1-jdk-amd64" \
           "/Library/Java/JavaVirtualMachines/temurin-$1.jdk/Contents/Home"; do
    [ -x "$c/bin/java" ] && { printf '%s\n' "$c"; return; }
  done
  return 0
}

# JDK major version (1.8 -> 8), from its release file or else `java -version`; empty if unknown.
java_major() {
  local v
  v="$(sed -n 's/^JAVA_VERSION="\(1\.\)\{0,1\}\([0-9][0-9]*\).*/\2/p' "$1/release" 2>/dev/null || true)"
  [ -n "$v" ] || v="$("$1/bin/java" -version 2>&1 | sed -n 's/.*version "\(1\.\)\{0,1\}\([0-9][0-9]*\).*/\2/p' | head -1 || true)"
  printf '%s\n' "$v"
}

GHIDRA="$(resolve_ghidra)"
[ -n "$GHIDRA" ] && [ -x "$GHIDRA/support/analyzeHeadless" ] || \
  die "no Ghidra install found; set GHIDRA_INSTALL_DIR"
JMIN="$(tr -d '\r' < "$GHIDRA/Ghidra/application.properties" 2>/dev/null | \
  sed -n 's/^[[:space:]]*application\.java\.min[[:space:]]*[=:][[:space:]]*\([0-9][0-9]*\).*/\1/p' | head -1 || true)"
if [ -n "$JMIN" ]; then
  JH="$(resolve_java_home "$JMIN")"
  [ -n "$JH" ] || die "no JDK $JMIN found; set JAVA_HOME (this Ghidra needs JDK $JMIN)"
  JV="$(java_major "$JH")"
  [ -z "$JV" ] || [ "$JV" -ge "$JMIN" ] || \
    die "JAVA_HOME is JDK $JV; this Ghidra needs JDK $JMIN or newer"
else
  # No declared minimum: require JAVA_HOME and use it unchecked.
  [ -n "${JAVA_HOME:-}" ] && [ -x "$JAVA_HOME/bin/java" ] || \
    die "cannot read application.java.min from $GHIDRA; set JAVA_HOME"
  JH="$JAVA_HOME"
fi

export PATH="$JH/bin:$PATH"
# Ghidra writes under $HOME during bootstrap; keep that inside the workspace so
# the build works in CI and inside a sandbox.
mkdir -p "$WORK/home" "$WORK/gradle" "$WORK/project"
WORK="$(cd "$WORK" && pwd)"
rm -f "$WORK/archive-path.txt"
export _JAVA_OPTIONS="-Duser.home=$WORK/home"
export GRADLE_USER_HOME="${GRADLE_USER_HOME:-$WORK/gradle}"

note "environment"
printf '  Ghidra    : %s\n  JDK       : %s\n  user.home : %s\n' \
  "$GHIDRA" "$JH" "$WORK/home"

note "compiling SLEIGH"
for spec in "$ROOT"/data/languages/*.slaspec; do
  ( cd "$ROOT" && "$GHIDRA/support/sleigh" "$spec" )
done
for sla in "$ROOT"/data/languages/*.sla; do
  [ -f "$sla" ] || die "SLEIGH produced no .sla - the extension would be unloadable"
  printf '  %s\n' "$(basename "$sla")"
done

note "building extension"
( cd "$ROOT" && "$GHIDRA/support/gradle/gradlew" --no-watch-fs -q \
    -PGHIDRA_INSTALL_DIR="$GHIDRA" buildExtension )
GVERSION="$(sed -n 's/^application.version=//p' "$GHIDRA/Ghidra/application.properties" | tr -d '\r')"
DIST="$(cat "$ROOT/build/release-archive-path.txt")"
[ -f "$DIST" ] || die "buildExtension produced no zip"

note "verifying zip contents"
python3 "$ROOT/tools/check_archive.py" "$DIST" --ghidra-version "$GVERSION"
printf '%s\n' "$DIST" > "$WORK/archive-path.txt"
printf '  %s\n' "$DIST"

if [ "${1:-}" = "--install" ]; then
  TARGET="${2:-${LOCAL_GHIDRA:-}}"
  [ -n "$TARGET" ] || die "--install needs a target Ghidra directory"
  [ -d "$TARGET/Ghidra" ] || die "not a Ghidra install: $TARGET"
  note "installing into $TARGET"
  rm -rf "$TARGET/Ghidra/Extensions/C6000"
  mkdir -p "$TARGET/Ghidra/Extensions"
  unzip -q -o "$DIST" -d "$TARGET/Ghidra/Extensions/"
  printf '  installed\n'
fi

note "ok"
