#!/usr/bin/env bash
# Compile the MSL suite outside the UL GUI, for CI or a quick syntax check.
#
# Inside the tool: Tools > Options > Java, set Output Path to build/ and add
# build/ to the Class Path, then compile lib/ first and the scripts after.
# Same arrangement as sim-os-atp - if that one already runs, this one needs no
# new configuration.
set -u

UL_HOME="${UL_HOME:-C:/Program Files (x86)/UL Test Tools/UL Mobile Card Test Platform 3.8.0 [7]}"
UL_LIB="$UL_HOME/lib/main"
SDK="$UL_LIB/ul-scripttool.jar"
TOOLS="$UL_LIB/tools.jar"

if [ ! -f "$SDK" ]; then
  echo "UL SDK not found at: $SDK" >&2
  echo "Set UL_HOME to the UL Mobile Card Test Platform install directory." >&2
  exit 2
fi

# Everything compiles into one output folder in the default package, matching
# how the UL script editor compiles a single .java at a time.
# OUT is where the .class files land. It defaults to ./build for a CI-style
# syntax check, but the UL GUI only ever looks in its own configured Output Path
# (Tools > Options > Java), so point OUT at that folder when you want the tool
# itself to pick the scripts up:
#
#   OUT="C:/Users/user/OneDrive/Documents/TAR/Clases" ./build.sh lib/*.java scripts/*.java
#
# Re-run it after any change under lib/ -- the scripts reference those classes by
# name, so a stale lib/ in the output folder is a silently wrong run, not a
# compile error.
OUT="${OUT:-build}"

CP="$SDK;$OUT"
mkdir -p "$OUT"

TARGETS="${*:-lib/*.java scripts/*.java selftest/*.java}"

# shellcheck disable=SC2086
java -cp "$TOOLS" com.sun.tools.javac.Main \
     -source 8 -target 8 -nowarn \
     -cp "$CP" -d "$OUT" $TARGETS
