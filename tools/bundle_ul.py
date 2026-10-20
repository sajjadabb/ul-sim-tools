"""
Bundles the UL scripts into ONE .java file, for the UL editor.

    python tools/bundle_ul.py              # writes ul/MslScript.java
    python tools/bundle_ul.py --check      # fails if that file is out of date

Why this exists:

The UL script editor compiles one .java at a time. The tool is ten files -
MslCore, MslCapLoad, MslProbing, MslConfig, MslConfigDialog, MslProfile,
MslLog, MslReport, UlChoices and the script itself - so compiling it from
inside the GUI means pressing Compile ten times, in dependency order, and
missing one leaves a stale class in the output folder that fails as
"cannot find symbol" in a file that is perfectly correct. That is a trap, and
an operator should not have to walk it.

Java allows any number of top-level classes in one file as long as at most one
is public and the file is named after it. So the bundle is simply every file's
body, with its imports hoisted to the top and the `public` keyword dropped from
the nine non-entry classes. Compiling that one file produces exactly the same
ten .class files, in one press.

The bundle is GENERATED, never edited: lib/ and scripts/ stay the source of
truth (they are what build.sh compiles, what the self-test runs against, and
what the Python port is diffed against). selftest.sh runs --check, so a bundle
that has drifted from the sources fails the gate rather than being discovered
on a card.
"""
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Order is for a human reading the file; javac does not care. Lowest-level
# first, the script last, which is also roughly the dependency order the UL
# editor would otherwise force you to click through by hand.
SOURCES = [
    "lib/MslCore.java",
    "lib/MslCapLoad.java",
    "lib/MslProbing.java",
    "lib/MslProfile.java",
    "lib/MslLog.java",
    "lib/MslReport.java",
    "lib/UlChoices.java",
    "lib/MslConfig.java",
    "lib/MslConfigDialog.java",
    "scripts/MslScript.java",
]

ENTRY = "scripts/MslScript.java"          # the one class that stays public
OUTPUT = "ul/MslScript.java"

IMPORT = re.compile(r"^\s*import\s+[\w.]+\s*;\s*$")
PACKAGE = re.compile(r"^\s*package\s+[\w.]+\s*;\s*$")
TOP_LEVEL_CLASS = re.compile(r"^public\s+((final|abstract)\s+)?(class|interface|enum)\s")

HEADER = """// GENERATED FILE - do not edit. Regenerate with:
//
//     python tools/bundle_ul.py
//
// This is every class the UL scripts need, in one file, because the UL script
// editor compiles one .java at a time. The sources are lib/*.java and
// scripts/MslScript.java; selftest.sh checks this file still matches them.
//
// In UL: Tools > Options > Java, set the Output Path to the folder on the
// Class Path, open this file, press Compile once, then close and reopen UL so
// the new classes are loaded. Running build.sh instead does the same job from
// the command line and does not need this file.
//
// Compile this file ON ITS OWN. Handing it to javac together with lib/*.java
// is ten duplicate classes and will not compile - which is also why it lives
// in ul/ rather than beside the sources build.sh globs.
//
// Bundled: %s
"""


def read(path):
    with open(os.path.join(ROOT, path), "r", encoding="utf-8") as handle:
        return handle.read()


def strip_file(path, text):
    """Returns (imports, body) with the body's top-level `public` removed."""
    imports = []
    body = []
    demoted = False

    for line in text.split("\n"):
        if PACKAGE.match(line):
            raise SystemExit("%s declares a package; the UL scripts are in the default "
                             "package and the bundle assumes it" % path)
        if IMPORT.match(line):
            imports.append(line.strip())
            continue

        if not demoted and TOP_LEVEL_CLASS.match(line):
            demoted = True
            if path != ENTRY:
                # Only one class in a file may be public, and it has to be the
                # one the file is named after - which is the script UL runs.
                line = line[len("public "):]
        body.append(line)

    if not demoted:
        raise SystemExit("%s has no top-level public class; the bundler cannot place it" % path)
    return imports, "\n".join(body).strip("\n")


def build():
    imports = []
    bodies = []

    for path in SOURCES:
        file_imports, body = strip_file(path, read(path))
        for entry in file_imports:
            if entry not in imports:
                imports.append(entry)
        bodies.append("// " + "-" * 74 + "\n// " + path + "\n// " + "-" * 74 + "\n\n" + body)

    # Imports grouped the way the sources group them: the SDK's own packages
    # first, then the JDK, so a reader can see at a glance what this file needs
    # from the platform.
    sdk = sorted(i for i in imports if not i.startswith("import java"))
    jdk = sorted(i for i in imports if i.startswith("import java"))

    out = [HEADER % ", ".join(os.path.basename(p) for p in SOURCES)]
    if sdk:
        out.append("\n".join(sdk))
    if jdk:
        out.append("\n".join(jdk))
    out.append("\n\n".join(bodies))
    return "\n\n".join(out) + "\n"


def main():
    bundle = build()
    target = os.path.join(ROOT, OUTPUT)

    if "--check" in sys.argv:
        if not os.path.isfile(target):
            print("MISSING: %s - run: python tools/bundle_ul.py" % OUTPUT)
            return 1
        with open(target, "r", encoding="utf-8") as handle:
            current = handle.read()
        if current != bundle:
            print("OUT OF DATE: %s no longer matches lib/ and scripts/." % OUTPUT)
            print("Regenerate it with: python tools/bundle_ul.py")
            return 1
        print("ok    %s is in step with lib/ and scripts/" % OUTPUT)
        return 0

    directory = os.path.dirname(target)
    if not os.path.isdir(directory):
        os.makedirs(directory)
    with open(target, "w", encoding="utf-8") as handle:
        handle.write(bundle)

    lines = bundle.count("\n")
    print("wrote %s - %d lines, %d classes in one file" % (OUTPUT, lines, len(SOURCES)))
    print("In UL: open it, press Compile once, then close and reopen UL.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
