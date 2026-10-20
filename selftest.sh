#!/usr/bin/env bash
# Card-free checks over the MSL logic, both implementations. No reader, no card,
# no dongle. Run this before you need any of them.
#
# Expected: Java 409, Python 416, UI 38, capload 22 (26 with the operator's real
# CAP present), RAM end-to-end 95. The Python counts assume pycryptodomex:
# without it the packet builder checks and the whole end-to-end suite are
# skipped, and each prints a smaller number and says so.
set -u

here="$(cd "$(dirname "$0")" && pwd)"
cd "$here" || exit 2

status=0

echo "=== The single-file UL bundle is in step with lib/ and scripts/ ==="
# The UL editor compiles one .java at a time, so ul/MslScript.java carries
# every class in one file. It is generated: a bundle that has drifted from the
# sources would compile into a card session nobody could explain.
if command -v python >/dev/null 2>&1; then
  python tools/bundle_ul.py --check || status=1
elif command -v python3 >/dev/null 2>&1; then
  python3 tools/bundle_ul.py --check || status=1
fi

echo
echo "=== Java (lib/, used by the UL scripts) ==="
# The SDK jar is on the RUN classpath as well as the compile one: UlChoices
# drives the dropdowns from the SDK's own enums, and the self-test checks those
# against this tool's integers. Still card-free - it needs the library, not a
# reader.
UL_HOME="${UL_HOME:-C:/Program Files (x86)/UL Test Tools/UL Mobile Card Test Platform 3.8.0 [7]}"
SDK="$UL_HOME/lib/main/ul-scripttool.jar"

if ./build.sh lib/*.java selftest/*.java; then
  java -cp "build;$SDK" MslSelfTest || status=1
else
  echo "compile failed" >&2
  status=1
fi

echo
echo "=== Python (tools/, used by the normal-mode tool) ==="
if command -v python >/dev/null 2>&1; then
  python tools/selftest_msl.py || status=1

  echo
  echo "=== Python GUI backend (tools/msl_ui.py) ==="
  # No display is opened: the window's rules live in msl_ui.Api and its layout
  # lives in ui/index.html, so the rules test as plain Python.
  python tools/selftest_ui.py || status=1

  echo
  echo "=== Python CAP loader (tools/capload.py) ==="
  python tools/selftest_capload.py || status=1

  echo
  echo "=== End to end over a simulated card (browse, delete, ota-install) ==="
  # Nothing in msl_tool.py is mocked here: pyscard is replaced by a card that
  # unwraps the envelope and the secured packet, executes the APDU inside it
  # like a card manager - SHA-1 of the reassembled load file included - and
  # answers with a response packet behind 61xx. It is the only test that
  # exercises the loop rather than the pieces.
  python tools/selftest_ram.py || status=1
else
  echo "python not on PATH - skipped" >&2
fi

exit $status
