"""
Card-free checks over capload.py — the CAP → LOAD sequence builder.

Serialization is the part that must be exactly right before an irreversible
INSTALL, so these checks reconstruct the load file from the blocks and verify
every length field, against the operator's real MobilePaymentApplet.cap when it
is present (and a synthetic CAP otherwise, so the suite runs anywhere).

    python tools/selftest_capload.py
"""
import io
import os
import sys
import zipfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import capload as c

PASSED = []
FAILED = []


def check(desc, cond, detail=""):
    (PASSED if cond else FAILED).append(desc)
    print(("ok    " if cond else "FAIL  ") + desc + (("  -- " + str(detail)) if (detail and not cond) else ""))


def make_synthetic_cap(path):
    """A minimal but structurally valid CAP: Header with a known AID + a few components."""
    def header(aid):
        # tag(1) size(2) magic(DECAFFED) capMinor capMajor flags pMinor pMajor aidlen aid
        body = b"\xDE\xCA\xFF\xED" + bytes([1, 2, 0, 1, 5, len(aid)]) + aid
        return bytes([1]) + len(body).to_bytes(2, "big") + body

    def applet(aids):
        body = bytes([len(aids)])
        for a in aids:
            body += bytes([len(a)]) + a + b"\x00\x11"   # AID + install_method_offset
        return bytes([3]) + len(body).to_bytes(2, "big") + body

    def comp(tag, payload):
        return bytes([tag]) + len(payload).to_bytes(2, "big") + payload

    with zipfile.ZipFile(path, "w") as z:
        z.writestr("SYN/javacard/Header.cap", header(bytes.fromhex("A00000006201")))
        z.writestr("SYN/javacard/Directory.cap", comp(2, b"\x01\x02\x03"))
        z.writestr("SYN/javacard/Applet.cap", applet([bytes.fromhex("A0000000620101")]))
        z.writestr("SYN/javacard/Import.cap", comp(4, b"\x00"))
        z.writestr("SYN/javacard/Method.cap", comp(7, b"\xAA" * 300))
        z.writestr("SYN/javacard/Debug.cap", comp(13, b"\xFF" * 50))  # must be EXCLUDED


SYN = os.path.join(os.path.dirname(os.path.abspath(__file__)), "_syn.cap")
make_synthetic_cap(SYN)

# ---------------------------------------------------------------------------
# Structure on the synthetic CAP (deterministic, runs anywhere)
# ---------------------------------------------------------------------------

check("package AID is read from the Header component",
      c.package_aid(SYN) == bytes.fromhex("A00000006201"),
      c.package_aid(SYN).hex())
check("applet AID is read from the Applet component",
      c.applet_aids(SYN) == [bytes.fromhex("A0000000620101")])

lf = c.load_file_data_block(SYN)
check("the Debug component is excluded from the load file", b"\xFF" * 50 not in lf)
check("the Method component IS in the load file", b"\xAA" * 300 in lf)

# INSTALL [for load] structure
inst = c.build_install_for_load(c.package_aid(SYN), lf)
check("INSTALL[for load] is 80 E6 02 00", inst[:4] == bytes.fromhex("80E60200"))
check("INSTALL[for load] Lc matches its data", inst[4] == len(inst) - 5)
# data = LV(ELF) LV(SD=empty) LV(hash=20) LV(params=empty) LV(token=empty)
check("INSTALL[for load] carries the 20-byte SHA-1 hash",
      bytes([20]) + c.load_file_hash(lf) in inst)

# LOAD blocks: reassemble and verify against C4 + BER(len) + load file
blocks = c.build_load_blocks(lf, block_size=160)
reassembled = bytearray()
for i, b in enumerate(blocks):
    check("LOAD block %d is 80 E8" % i, b[0] == 0x80 and b[1] == 0xE8)
    check("LOAD block %d Lc matches its chunk" % i, b[4] == len(b) - 5)
    last = (i == len(blocks) - 1)
    check("LOAD block %d P1 last-bit is %s" % (i, last),
          bool(b[2] & 0x80) == last, "P1=%02X" % b[2])
    check("LOAD block %d seq is %d" % (i, i), b[3] == i)
    reassembled += b[5:]

check("reassembled blocks start with tag C4", reassembled[0] == 0xC4)
# strip C4 + BER length, the rest must equal the load file
i = 1
if reassembled[1] & 0x80:
    i = 2 + (reassembled[1] & 0x7F)
else:
    i = 2
check("reassembled load file equals the original", bytes(reassembled[i:]) == lf,
      "%d vs %d bytes" % (len(reassembled) - i, len(lf)))

check("every LOAD block fits a single SMS-PP envelope (<=197 B secured data)",
      all(len(b) <= 197 for b in blocks), max(len(b) for b in blocks))

# ---------------------------------------------------------------------------
# The operator's real CAP, when present
# ---------------------------------------------------------------------------

REAL = r"C:\Users\user\OneDrive\Desktop\develope new ssd\MobilePaymentApplet.cap"
if os.path.isfile(REAL):
    check("real CAP: package AID is 1122334455",
          c.package_aid(REAL) == bytes.fromhex("1122334455"))
    check("real CAP: applet AID is 112233445500",
          c.applet_aids(REAL) == [bytes.fromhex("112233445500")])
    elf, apdus = c.build_load_sequence(REAL, block_size=160)
    check("real CAP: load sequence is INSTALL[for load] + LOAD blocks",
          apdus[0][:4] == bytes.fromhex("80E60200") and all(a[1] == 0xE8 for a in apdus[1:]))
    check("real CAP: every APDU fits a single OTA envelope",
          all(len(a) <= 197 for a in apdus), max(len(a) for a in apdus))
else:
    print("note: real MobilePaymentApplet.cap not found - skipped its checks")

try:
    os.remove(SYN)
except OSError:
    pass

print()
print("%d passed, %d failed" % (len(PASSED), len(FAILED)))
sys.exit(1 if FAILED else 0)
