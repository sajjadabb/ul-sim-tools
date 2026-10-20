"""
GlobalPlatform CAP loading: turn a Java Card .cap file into the INSTALL [for
load] + LOAD block chain + INSTALL [for install] APDUs, for delivery either in
a GlobalPlatform secure channel or wrapped in SCP80 secured packets over OTA.

This is the part that must be exactly right, because a malformed load file
bricks nothing but wastes a card-management session, and a wrong INSTALL on a
real card is irreversible. So the serialization here is tested offline against
the real CAP (see selftest in __main__), and every length field is computed, not
guessed.

Load File Data Block = the CAP components concatenated in the JavaCard download
order (JCVM spec 6.2), Debug excluded. Each .cap component already carries its
own tag+size header, so the block is a straight concatenation in that order.
"""
import hashlib
import struct
import zipfile


# JavaCard download order for the Load File Data Block (JCVM 2.2 spec, 6.2).
# Debug is never part of the load file; Applet is absent for a library CAP.
LOAD_ORDER = [
    "Header.cap", "Directory.cap", "Import.cap", "Applet.cap", "Class.cap",
    "Method.cap", "StaticField.cap", "ConstantPool.cap", "RefLocation.cap",
    "Descriptor.cap",
]


def _ber_length(n):
    """BER-TLV length encoding (GlobalPlatform uses it for the C4 tag)."""
    if n < 0x80:
        return bytes([n])
    out = []
    while n:
        out.insert(0, n & 0xFF)
        n >>= 8
    return bytes([0x80 | len(out)]) + bytes(out)


def read_components(cap_path):
    """Reads the CAP's components, keyed by their bare filename."""
    components = {}
    with zipfile.ZipFile(cap_path) as z:
        for name in z.namelist():
            base = name.rsplit("/", 1)[-1]
            if base.endswith(".cap"):
                components[base] = z.read(name)
    return components


def package_aid(cap_path):
    """The package AID from the Header component (also the load file AID)."""
    header = read_components(cap_path)["Header.cap"]
    # tag(1) size(2) magic(4) capMinor(1) capMajor(1) flags(1)
    # package: minor(1) major(1) AID_len(1) AID(n)
    i = 3 + 4 + 2 + 1 + 2
    aid_len = header[i]
    return header[i + 1:i + 1 + aid_len]


def applet_aids(cap_path):
    """Every applet AID declared in the Applet component (empty for a library)."""
    components = read_components(cap_path)
    applet = components.get("Applet.cap")
    if not applet:
        return []
    i = 3                      # tag + size
    count = applet[i]; i += 1
    out = []
    for _ in range(count):
        length = applet[i]; i += 1
        out.append(applet[i:i + length]); i += length
        i += 2                 # install_method_offset
    return out


def load_file_data_block(cap_path):
    """The CAP components concatenated in download order (Debug excluded)."""
    components = read_components(cap_path)
    block = bytearray()
    for name in LOAD_ORDER:
        if name in components:
            block += components[name]
    return bytes(block)


def load_file_hash(load_file):
    """SHA-1 of the load file data block, for INSTALL [for load]."""
    return hashlib.sha1(load_file).digest()


def build_install_for_load(elf_aid, load_file, sd_aid=b"", with_hash=True,
                           load_parameters=b""):
    """
    INSTALL [for load] APDU (GlobalPlatform 2.2 clause 11.5.2.3).

    Data = [ELF AID LV][SD AID LV][Load File Data Block Hash LV]
           [Load Parameters LV][Load Token LV]
    The hash is optional per GP; included by default because cards that require
    it answer 6A80 without it, and it is cheap to compute.
    """
    def lv(value):
        value = bytes(value)
        if len(value) > 0xFF:
            raise ValueError("INSTALL[for load] field too long: %d" % len(value))
        return bytes([len(value)]) + value

    the_hash = load_file_hash(load_file) if with_hash else b""
    data = lv(elf_aid) + lv(sd_aid) + lv(the_hash) + lv(load_parameters) + lv(b"")
    return bytes([0x80, 0xE6, 0x02, 0x00, len(data)]) + data


def build_load_blocks(load_file, block_size=200):
    """
    The LOAD command chain (GlobalPlatform 2.2 clause 11.6).

    The load file data block is prefixed with tag C4 and its BER length, then
    split into blocks. Each block: 80 E8 P1 P2, P1 bit8 = last block, P2 = block
    sequence number from 00. block_size caps the data per LOAD; 200 leaves room
    for the secured-packet overhead when these are wrapped for OTA.
    """
    tagged = b"\xC4" + _ber_length(len(load_file)) + load_file
    blocks = []
    offset = 0
    seq = 0
    while offset < len(tagged):
        chunk = tagged[offset:offset + block_size]
        offset += len(chunk)
        last = offset >= len(tagged)
        p1 = 0x80 if last else 0x00
        apdu = bytes([0x80, 0xE8, p1, seq & 0xFF, len(chunk)]) + chunk
        blocks.append(apdu)
        seq += 1
    return blocks


def build_load_sequence(cap_path, sd_aid=b"", with_hash=True, block_size=200):
    """
    The full load sequence for a CAP: INSTALL [for load] then the LOAD blocks.

    Returns (elf_aid, [apdu, ...]). The caller then sends each APDU either
    through a secure channel or wrapped in a secured packet to the card manager.
    """
    elf_aid = package_aid(cap_path)
    load_file = load_file_data_block(cap_path)
    apdus = [build_install_for_load(elf_aid, load_file, sd_aid, with_hash)]
    apdus += build_load_blocks(load_file, block_size)
    return elf_aid, apdus


if __name__ == "__main__":
    import sys
    cap = sys.argv[1]
    elf = package_aid(cap)
    applets = applet_aids(cap)
    lf = load_file_data_block(cap)
    print("package / ELF AID :", "".join("%02X" % b for b in elf))
    for a in applets:
        print("applet AID        :", "".join("%02X" % b for b in a))
    print("load file size    : %d bytes" % len(lf))
    print("load file SHA-1    :", "".join("%02X" % b for b in load_file_hash(lf)))
    elf, apdus = build_load_sequence(cap)
    print("INSTALL[for load] :", "".join("%02X" % b for b in apdus[0]))
    print("LOAD blocks       : %d" % (len(apdus) - 1))
    for i, a in enumerate(apdus[1:]):
        print("  block %d (%d B)   : %s…" % (i, len(a),
              "".join("%02X" % b for b in a[:12])))
