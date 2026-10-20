"""
The MSL logic itself: nothing here touches a card, a reader or the UL platform.

Everything in this module is a pure function over bytes, which is deliberate --
it is the part that has to be right, and it is the part that can be tested
without a card (see selftest_msl.py). The card-facing code (msl_tool.py -- the
packet builder, the reader and the CLI) is a thin shell around it, and the Java
lib/ classes used by the UL scripts mirror this file class for class so the two
implementations can be diffed against each other.

Governing specs:
  ETSI TS 102 225 -- secured packet structure, SPI coding (clause 5.1.1)
  ETSI TS 102 226 -- UICC toolkit application specific parameters, MSL (clause 8.2.1.3.2)
  GlobalPlatform Card Specification 2.2 -- INSTALL [for install and make selectable]

What MSL is, in one paragraph, because the whole tool follows from it:
an applet installed on a UICC carries a Minimum Security Level, fixed at install
time in its install parameters. When a secured packet arrives for that applet's
TAR, the card compares the security the packet actually applied (SPI first
octet) against the MSL, and rejects the packet with response status 0A
("insufficient security level") BEFORE checking the MAC or the counter. That is
what makes MSL testable at all: 0A is a distinct, observable answer that no
wrong key and no stale counter can produce.
"""

# ---------------------------------------------------------------------------
# The three axes of the MSL / SPI first octet
# ---------------------------------------------------------------------------
#
# TS 102 225 clause 5.1.1, first octet of the SPI:
#   b2 b1   integrity applied to the command packet
#   b3      ciphering
#   b5 b4   counter checking policy
#   b8-b6   reserved, zero
#
# TS 102 226 codes the MSL parameter byte the same way, which is what lets a
# single pair of encode/decode functions serve both.

INTEGRITY_NONE = 0
INTEGRITY_RC = 1
INTEGRITY_CC = 2
INTEGRITY_DS = 3

CIPHER_OFF = 0
CIPHER_ON = 1

COUNTER_NONE = 0
COUNTER_NO_CHECK = 1
COUNTER_HIGHER = 2
COUNTER_ONE_HIGHER = 3

INTEGRITY_NAMES = {
    INTEGRITY_NONE: "no integrity",
    INTEGRITY_RC: "redundancy check",
    INTEGRITY_CC: "cryptographic checksum",
    INTEGRITY_DS: "digital signature",
}
CIPHER_NAMES = {CIPHER_OFF: "no ciphering", CIPHER_ON: "ciphering"}
COUNTER_NAMES = {
    COUNTER_NONE: "no counter",
    COUNTER_NO_CHECK: "counter present, not checked",
    COUNTER_HIGHER: "counter must be higher",
    COUNTER_ONE_HIGHER: "counter must be exactly one higher",
}

AXES = ("integrity", "cipher", "counter")
AXIS_MAX = {"integrity": INTEGRITY_DS, "cipher": CIPHER_ON, "counter": COUNTER_ONE_HIGHER}
AXIS_NAMES = {"integrity": INTEGRITY_NAMES, "cipher": CIPHER_NAMES, "counter": COUNTER_NAMES}


class MslLevel(object):
    """
    One Minimum Security Level: the three axis values plus any trailing MSL data.

    MSL data is the optional remainder of the "Minimum Security Level" field
    after the first byte (TS 102 226 clause 8.2.1.3.2). It is card- and
    profile-specific, so this class carries it verbatim and never invents one.
    """

    def __init__(self, integrity=INTEGRITY_NONE, cipher=CIPHER_OFF,
                 counter=COUNTER_NONE, data=b""):
        for name, value in (("integrity", integrity), ("cipher", cipher), ("counter", counter)):
            if not 0 <= value <= AXIS_MAX[name]:
                raise ValueError("%s out of range: %r" % (name, value))
        self.integrity = integrity
        self.cipher = cipher
        self.counter = counter
        self.data = bytes(data)

    # -- encoding ----------------------------------------------------------

    def to_byte(self):
        """The MSL parameter byte, identically coded to the SPI first octet."""
        return (self.integrity & 0x03) | ((self.cipher & 0x01) << 2) | ((self.counter & 0x03) << 3)

    def to_field(self):
        """The whole 'Minimum Security Level' field: parameter byte then MSL data."""
        return bytes(bytearray([self.to_byte()])) + self.data

    @staticmethod
    def from_byte(value, data=b""):
        if not 0 <= value <= 0xFF:
            raise ValueError("MSL byte out of range: %r" % (value,))
        if value & 0xE0:
            # Not fatal -- a card may use the reserved bits for something
            # proprietary -- but the caller should see it rather than have it
            # silently dropped on the next re-encode.
            raise ValueError("MSL byte %02X sets reserved bits b6-b8; "
                             "pass it as raw MSL data instead of a decoded level" % value)
        return MslLevel(value & 0x03, (value >> 2) & 0x01, (value >> 3) & 0x03, data)

    @staticmethod
    def from_field(field):
        field = bytes(field)
        if not field:
            # A zero-length MSL field is legal and means "no minimum enforced".
            return None
        return MslLevel.from_byte(field[0] if isinstance(field[0], int) else ord(field[0]),
                                  field[1:])

    # -- comparison --------------------------------------------------------

    def axis(self, name):
        return getattr(self, name)

    def with_axis(self, name, value):
        fields = {"integrity": self.integrity, "cipher": self.cipher, "counter": self.counter}
        fields[name] = value
        return MslLevel(data=self.data, **fields)

    def dominates(self, other):
        """
        True when this level provides at least `other` on every axis.

        This is the field-wise comparison an MSL check is normally implemented
        as. It is used here only to PREDICT what a card should do -- the
        discovery routine measures each axis separately and never assumes it,
        precisely because TS 102 226 does not spell the comparison out
        byte-for-byte and implementations have been seen to differ.
        """
        return (self.integrity >= other.integrity
                and self.cipher >= other.cipher
                and self.counter >= other.counter)

    def describe(self):
        return "%02X (%s, %s, %s)%s" % (
            self.to_byte(),
            INTEGRITY_NAMES[self.integrity],
            CIPHER_NAMES[self.cipher],
            COUNTER_NAMES[self.counter],
            "" if not self.data else " + MSL data %s" % hexs(self.data),
        )

    def __eq__(self, other):
        return (isinstance(other, MslLevel)
                and self.to_byte() == other.to_byte()
                and self.data == other.data)

    def __ne__(self, other):
        return not self.__eq__(other)

    def __hash__(self):
        return hash((self.to_byte(), self.data))

    def __repr__(self):
        return "MslLevel(%s)" % self.describe()


def spi_first_octet(integrity, cipher, counter):
    """The SPI first octet for a packet built at this security -- same coding as MSL."""
    return (integrity & 0x03) | ((cipher & 0x01) << 2) | ((counter & 0x03) << 3)


def hexs(data):
    return "".join("%02X" % b for b in bytearray(data))


def unhex(text):
    text = "".join(text.split()).replace(":", "")
    if len(text) % 2:
        raise ValueError("odd number of hex digits: %r" % text)
    return bytes(bytearray(int(text[i:i + 2], 16) for i in range(0, len(text), 2)))


# ---------------------------------------------------------------------------
# TS 102 226 install parameters
# ---------------------------------------------------------------------------
#
# The install parameters field of INSTALL [for install and make selectable]
# carries, in TLV form:
#
#   C9 <len> <application specific parameters>     GlobalPlatform, the applet's own
#   EF <len> <system specific parameters>          GlobalPlatform (C7 volatile / C8 non-volatile)
#   EA <len> CA <len> <UICC toolkit parameters>    ETSI TS 102 226
#
# and the toolkit parameters (tag CA) are a fixed-order sequence of plain
# fields -- not TLVs -- ending with the two length-prefixed variable fields this
# tool exists for:
#
#   priority                                  1
#   maximum number of timers                  1
#   maximum text length of a menu entry       1
#   maximum number of menu entries      n =   1
#   position + identifier per menu entry     2n
#   maximum number of channels                1
#   length of the Minimum Security Level      1
#   Minimum Security Level                  var    <-- MSL parameter byte + MSL data
#   length of the TAR field                   1
#   TAR value(s)                            3*m
#
# READ THIS BEFORE THE FIRST INSTALL ON A CARD YOU CARE ABOUT. That field order
# is this tool's reading of TS 102 226 clause 8.2.1.3.2, and there is no copy of
# the spec text on this machine to check it against. One hard data point
# supports the MSL byte itself: the operator's vendor spreadsheet documents MSL
# 0x12 as "Counter Higher, CC, No Ciphering", which is exactly what MslLevel
# decodes 0x12 to. That confirms the byte, not the field order around it.
# describe_install_parameters() prints every byte with the field this tool
# assigned it to, so the order can be read against the spec in one pass; if your
# profile disagrees, --raw-params takes the whole field as hex and bypasses this
# builder entirely.

TAG_APPLICATION_SPECIFIC = 0xC9
TAG_SYSTEM_SPECIFIC = 0xEF        # GlobalPlatform System Specific
TAG_UICC_SYSTEM_SPECIFIC = 0xEA   # ETSI UICC System Specific
TAG_SIM_TOOLKIT = 0xCA            # CA: SIM-format toolkit, lives in EF
TAG_UICC_TOOLKIT = 0x80           # 80: UICC-format toolkit, lives in EA
TAG_UICC_ACCESS = 0x81
TAG_UICC_ADMIN_ACCESS = 0x82

# The two install-parameter formats of ETSI TS 102 226 clause 8.2.1.3.2,
# confirmed from the spec PDF (V9.4.0):
#   UICC: tag 'EA' wrapping tag '80'.   SIM: tag 'EF' wrapping tag 'CA'.
# Both 'CA' and 'EA' present -> the card returns 6A80, so EA{CA} was a malformed
# cross of the two. The inner byte order is identical, so one encoder serves both.
FORMAT_UICC = 0
FORMAT_SIM = 1


def _toolkit_tag(fmt):
    return TAG_SIM_TOOLKIT if fmt == FORMAT_SIM else TAG_UICC_TOOLKIT


def _system_tag(fmt):
    return TAG_SYSTEM_SPECIFIC if fmt == FORMAT_SIM else TAG_UICC_SYSTEM_SPECIFIC


def _tlv(tag, value):
    value = bytes(value)
    if len(value) > 0xFF:
        raise ValueError("this builder only emits short-form lengths; tag %02X would need %d bytes"
                         % (tag, len(value)))
    return bytes(bytearray([tag, len(value)])) + value


def tlv_remainder(data):
    """
    How many trailing bytes a short-form TLV walk could not consume. Zero means
    the field is well formed all the way to its end.

    _walk_tlv below is deliberately tolerant - it stops at the first bad length
    and yields what it read, which is right for anything a card hands back. That
    tolerance is wrong in one place: a raw install parameters field pasted by an
    operator and about to be SENT. A truncated block there parses to "no MSL
    found", which is indistinguishable from a block that legitimately sets none,
    so it would go to the card unremarked. This is the check that tells those
    apart. Mirrors MslCore.tlvRemainder on the Java side.
    """
    if not data:
        return 0
    data = bytearray(data)
    pos = 0
    while pos + 1 < len(data):
        length = data[pos + 1]
        if pos + 2 + length > len(data):
            break
        pos += 2 + length
    return len(data) - pos


def _walk_tlv(data):
    """Short-form BER-TLV walk. Stops at the first length that overruns the buffer."""
    data = bytearray(data)
    pos = 0
    while pos + 1 < len(data):
        tag = data[pos]
        length = data[pos + 1]
        if pos + 2 + length > len(data):
            break
        yield tag, bytes(data[pos + 2:pos + 2 + length])
        pos += 2 + length


class MenuEntry(object):
    """One (position, identifier) pair; both 00 mean "the card decides"."""

    def __init__(self, position=0x00, identifier=0x00):
        self.position = position
        self.identifier = identifier


class ToolkitParameters(object):
    """
    The tag 'CA' content.

    Every field is an explicit argument with a conservative default, because
    "no timers, no menu entries, no channels" is the right shape for an applet
    installed only to have its MSL exercised, and anything else is a real
    provisioning decision that belongs to the operator, not to a default.
    """

    def __init__(self, msl, tars, priority=0x01, max_timers=0x00,
                 max_menu_text_length=0x00, menu_entries=None, max_channels=0x00):
        self.msl = msl                       # MslLevel, or None for "emit no MSL field"
        self.tars = [bytes(t) for t in (tars or [])]
        for tar in self.tars:
            if len(tar) != 3:
                raise ValueError("a TAR is 3 bytes, got %d (%s)" % (len(tar), hexs(tar)))
        self.priority = priority
        self.max_timers = max_timers
        self.max_menu_text_length = max_menu_text_length
        self.menu_entries = list(menu_entries or [])
        self.max_channels = max_channels

    def encode(self):
        out = bytearray()
        out.append(self.priority)
        out.append(self.max_timers)
        out.append(self.max_menu_text_length)
        out.append(len(self.menu_entries))
        for entry in self.menu_entries:
            out.append(entry.position)
            out.append(entry.identifier)
        out.append(self.max_channels)

        msl_field = b"" if self.msl is None else self.msl.to_field()
        out.append(len(msl_field))
        out.extend(bytearray(msl_field))

        tar_field = b"".join(self.tars)
        out.append(len(tar_field))
        out.extend(bytearray(tar_field))
        return bytes(out)


class ParsedToolkitParameters(object):
    def __init__(self):
        self.priority = None
        self.max_timers = None
        self.max_menu_text_length = None
        self.menu_entries = []
        self.max_channels = None
        self.msl = None
        self.msl_field = b""
        self.tars = []
        self.trailing = b""
        self.fields = []          # (offset, bytes, description), for the annotated dump


def parse_toolkit_parameters(data):
    """
    Decode a tag 'CA' value.

    Raises ValueError on truncation rather than returning a half-parsed object:
    a silently truncated parse is exactly how a wrong MSL gets reported as a
    right one.
    """
    data = bytearray(data)
    parsed = ParsedToolkitParameters()
    state = {"pos": 0}

    def take(count, description):
        pos = state["pos"]
        if pos + count > len(data):
            raise ValueError("toolkit parameters truncated: %s needs %d byte(s) at offset %d, "
                             "only %d left" % (description, count, pos, len(data) - pos))
        chunk = bytes(data[pos:pos + count])
        parsed.fields.append((pos, chunk, description))
        state["pos"] = pos + count
        return bytearray(chunk)

    parsed.priority = take(1, "priority level")[0]
    parsed.max_timers = take(1, "maximum number of timers")[0]
    parsed.max_menu_text_length = take(1, "maximum menu entry text length")[0]
    entry_count = take(1, "maximum number of menu entries")[0]
    for index in range(entry_count):
        pair = take(2, "menu entry %d (position, identifier)" % (index + 1))
        parsed.menu_entries.append(MenuEntry(pair[0], pair[1]))
    parsed.max_channels = take(1, "maximum number of channels")[0]

    msl_length = take(1, "length of the Minimum Security Level field")[0]
    if msl_length:
        parsed.msl_field = bytes(take(msl_length, "Minimum Security Level"))
        parsed.msl = MslLevel.from_field(parsed.msl_field)

    tar_length = take(1, "length of the TAR field")[0]
    if tar_length:
        if tar_length % 3:
            raise ValueError("TAR field is %d bytes, not a multiple of 3" % tar_length)
        tar_bytes = bytes(take(tar_length, "TAR value(s)"))
        parsed.tars = [tar_bytes[i:i + 3] for i in range(0, tar_length, 3)]

    if state["pos"] < len(data):
        parsed.trailing = bytes(data[state["pos"]:])
        parsed.fields.append((state["pos"], parsed.trailing,
                              "trailing bytes this parser did not consume"))
    return parsed


def build_install_parameters(toolkit, application_specific=b"", system_specific=None,
                             uicc_access=None, uicc_admin_access=None, fmt=FORMAT_UICC):
    """
    The complete install parameters field.

    C9 goes first and is emitted even when empty: GlobalPlatform requires the
    application specific parameters tag to be present, and a card that enforces
    that answers 6A80 to an otherwise perfect EA block.

    `fmt` picks the ETSI format: FORMAT_UICC emits EA{80}, FORMAT_SIM emits
    EF{CA}. Never EA{CA}, which the spec says the card rejects with 6A80.
    """
    out = bytearray()
    out.extend(bytearray(_tlv(TAG_APPLICATION_SPECIFIC, application_specific)))
    if system_specific:
        out.extend(bytearray(_tlv(TAG_SYSTEM_SPECIFIC, system_specific)))

    uicc = bytearray()
    if toolkit is not None:
        uicc.extend(bytearray(_tlv(_toolkit_tag(fmt), toolkit.encode())))
    if uicc_access:
        uicc.extend(bytearray(_tlv(TAG_UICC_ACCESS, uicc_access)))
    if uicc_admin_access:
        uicc.extend(bytearray(_tlv(TAG_UICC_ADMIN_ACCESS, uicc_admin_access)))
    if uicc:
        out.extend(bytearray(_tlv(_system_tag(fmt), bytes(uicc))))
    return bytes(out)


def find_toolkit_parameters(install_parameters):
    """
    Pull the tag 'CA' value out of an install parameters field, wherever it sits.

    Walks EA's children rather than assuming an offset, so it also reads back
    parameters built by some other tool. Returns None when there is no toolkit
    block at all -- which is itself an answer to "what MSL does this applet
    have": none was set at install time.
    """
    for tag, value in _walk_tlv(install_parameters):
        if tag in (TAG_UICC_TOOLKIT, TAG_SIM_TOOLKIT):
            return value
        if tag in (TAG_UICC_SYSTEM_SPECIFIC, TAG_SYSTEM_SPECIFIC):
            for inner_tag, inner_value in _walk_tlv(value):
                if inner_tag in (TAG_UICC_TOOLKIT, TAG_SIM_TOOLKIT):
                    return inner_value
    return None


def msl_of_install_parameters(install_parameters):
    """The MSL an install parameters field declares, or None when it declares none."""
    toolkit = find_toolkit_parameters(install_parameters)
    if toolkit is None:
        return None
    return parse_toolkit_parameters(toolkit).msl


def describe_install_parameters(install_parameters):
    """
    An annotated, byte-by-byte dump.

    This is the artefact to read against TS 102 226 before the first install:
    every byte is printed with the field this tool believes it to be. If a line
    looks wrong, the builder is wrong for your profile, and --raw-params is the
    way past it.
    """
    lines = []
    for tag, value in _walk_tlv(install_parameters):
        if tag == TAG_APPLICATION_SPECIFIC:
            lines.append("C9 %02X  application specific parameters%s"
                         % (len(value), " (empty)" if not value else " " + hexs(value)))
        elif tag in (TAG_SYSTEM_SPECIFIC, TAG_UICC_SYSTEM_SPECIFIC):
            container = "EF" if tag == TAG_SYSTEM_SPECIFIC else "EA"
            kind = "system specific parameters" if tag == TAG_SYSTEM_SPECIFIC \
                else "UICC system specific parameters"
            lines.append("%s %02X  %s" % (container, len(value), kind))
            for inner_tag, inner_value in _walk_tlv(value):
                if inner_tag in (TAG_UICC_TOOLKIT, TAG_SIM_TOOLKIT):
                    label = "UICC toolkit" if inner_tag == TAG_UICC_TOOLKIT else "SIM toolkit"
                    lines.append("  %02X %02X  %s application specific parameters"
                                 % (inner_tag, len(inner_value), label))
                    lines.extend(_describe_toolkit(inner_value))
                else:
                    lines.append("  %02X %02X  %s" % (inner_tag, len(inner_value), hexs(inner_value)))
        else:
            lines.append("%02X %02X  %s" % (tag, len(value), hexs(value)))
    return lines


def _describe_toolkit(value):
    lines = []
    try:
        parsed = parse_toolkit_parameters(value)
    except ValueError as error:
        return ["    !! %s" % error, "    raw: %s" % hexs(value)]
    for offset, chunk, description in parsed.fields:
        lines.append("    +%-3d %-14s %s" % (offset, hexs(chunk), description))
    if parsed.msl is not None:
        lines.append("    -> MSL %s" % parsed.msl.describe())
    else:
        lines.append("    -> no Minimum Security Level field: this applet enforces no minimum")
    for tar in parsed.tars:
        lines.append("    -> TAR %s" % hexs(tar))
    return lines


# ---------------------------------------------------------------------------
# INSTALL [for install and make selectable]
# ---------------------------------------------------------------------------

def build_install_apdu(load_file_aid, module_aid, instance_aid, install_parameters,
                       privileges=b"\x00", cla=0x80, make_selectable=True):
    """
    GlobalPlatform 2.2 clause 11.5: INSTALL, P1 = 0C for
    [for install and make selectable], P2 = 00, data a sequence of
    length-prefixed fields.

    make_selectable=False emits P1 = 04 ([for install] only). That leaves the
    applet INSTALLED but not SELECTABLE, and an applet that is not selectable is
    not reachable by its TAR either -- OTA answers 09 (TAR unknown) instead of
    anything about security. Leave it True unless you are deliberately testing
    that distinction.
    """
    def lv(value):
        value = bytes(value)
        if len(value) > 0xFF:
            raise ValueError("field too long for a single-byte length: %d bytes" % len(value))
        return bytes(bytearray([len(value)])) + value

    data = (lv(load_file_aid) + lv(module_aid) + lv(instance_aid)
            + lv(privileges) + lv(install_parameters) + lv(b""))   # empty install token
    if len(data) > 0xFF:
        raise ValueError("INSTALL data is %d bytes; this builder emits short Lc only" % len(data))
    header = bytearray([cla, 0xE6, 0x0C if make_selectable else 0x04, 0x00, len(data)])
    return bytes(header) + data


# ---------------------------------------------------------------------------
# Probing: what the card can be asked, and what its answers mean
# ---------------------------------------------------------------------------
#
# Nothing below sends anything. Each routine takes an `oracle` -- any callable
# that accepts a Probe and returns a ProbeResult -- so the same inference code
# runs against a real card (msl_tool.py), against the UL platform (the Java
# port in lib/), and against SimulatedCard in the self-test. That is the whole
# reason the algorithm is worth writing down separately from the transport.

ACCEPTED = "ACCEPTED"            # the card did not reject the packet on security grounds
BELOW_MSL = "BELOW_MSL"          # response status 0A -- insufficient security level
INCONCLUSIVE = "INCONCLUSIVE"    # no PoR, or an answer that says nothing about the MSL


class Probe(object):
    """One point in the (integrity, ciphering, counter) lattice."""

    def __init__(self, integrity, cipher, counter):
        self.integrity = integrity
        self.cipher = cipher
        self.counter = counter

    def key(self):
        return (self.integrity, self.cipher, self.counter)

    def spi_first_octet(self):
        return spi_first_octet(self.integrity, self.cipher, self.counter)

    def as_level(self):
        return MslLevel(self.integrity, self.cipher, self.counter)

    def describe(self):
        return "SPI1=%02X (%s, %s, %s)" % (
            self.spi_first_octet(),
            INTEGRITY_NAMES[self.integrity],
            CIPHER_NAMES[self.cipher],
            COUNTER_NAMES[self.counter],
        )

    def __repr__(self):
        return "Probe(%s)" % self.describe()


class ProbeResult(object):
    def __init__(self, probe, outcome, status=None, note=""):
        self.probe = probe
        self.outcome = outcome
        self.status = status        # the PoR response status byte, or None
        self.note = note

    def describe(self):
        status = "no PoR" if self.status is None else "status %02X" % self.status
        return "%-58s -> %-12s %s%s" % (self.probe.describe(), self.outcome, status,
                                        ("  " + self.note) if self.note else "")


def classify(status, por_received):
    """
    Turn a PoR into one of the three outcomes the inference works on.

    The one thing that matters here: the MSL check happens BEFORE the integrity
    and counter checks (TS 102 226), so 01 (RC/CC/DS failed), 02/03 (counter
    low/high) and even 09 all mean the packet got PAST the security-level gate.
    Treating them as failures would make the tool report an MSL of "everything
    is rejected" whenever the key was slightly wrong -- which is the single
    easiest way to get a confident wrong answer out of this kind of probing.
    """
    if not por_received or status is None:
        return INCONCLUSIVE, ("no PoR came back -- with no answer there is nothing to conclude "
                              "about the security level")
    if status == 0x0A:
        return BELOW_MSL, "insufficient security level"
    if status == 0x00:
        return ACCEPTED, ""
    if status in (0x01, 0x02, 0x03, 0x04, 0x05, 0x06):
        return ACCEPTED, ("the packet passed the security-level gate and then failed a later "
                          "check (status %02X) -- that is still evidence the MSL was met" % status)
    if status == 0x09:
        return INCONCLUSIVE, ("TAR unknown -- this TAR does not resolve to an installed, "
                              "selectable application, so no MSL is being applied at all")
    return ACCEPTED, "status %02X -- past the security-level gate" % status


class Ceiling(object):
    """
    The strongest packet the tooling in front of this card can actually build.

    This is not the card's limit, it is ours: no KIc key means no ciphering, a
    key set with no AES means no AES, and PROCESS_IF_ONE_HIGHER can only be sent
    once the card's own counter is known exactly. Discovery holds the two axes
    it is not measuring at these values, so an unreachable axis cannot be
    mistaken for a card that rejects everything.
    """

    def __init__(self, integrity=INTEGRITY_CC, cipher=CIPHER_OFF, counter=COUNTER_HIGHER):
        self.integrity = integrity
        self.cipher = cipher
        self.counter = counter

    def axis(self, name):
        return getattr(self, name)

    def probe_at(self, **overrides):
        values = {"integrity": self.integrity, "cipher": self.cipher, "counter": self.counter}
        values.update(overrides)
        return Probe(values["integrity"], values["cipher"], values["counter"])

    def describe(self):
        return "integrity <= %s, cipher <= %s, counter <= %s" % (
            INTEGRITY_NAMES[self.integrity], CIPHER_NAMES[self.cipher],
            COUNTER_NAMES[self.counter])


class Oracle(object):
    """Memoises probes so an axis walk never pays twice for the same point.

    silent_drop handles cards that do NOT return 0A for a below-MSL packet but
    instead discard it with no PoR (an anti-oracle hardening: without the key a
    card refuses to leak its security map). On such a card a drop is ambiguous -
    below-MSL, counter-too-low and a comms error all look alike - so it only
    becomes meaningful once a baseline probe has returned a PoR, which proves the
    key, counter, TAR and link are all good. From then on an INCONCLUSIVE (no
    PoR) can only be the axis just weakened, i.e. BELOW_MSL. Before any baseline
    PoR a drop stays INCONCLUSIVE, so a card that answers nothing at all is never
    misread as "rejects everything".
    """

    def __init__(self, send, budget=24, silent_drop=False):
        self.send = send
        self.budget = budget
        self.silent_drop = silent_drop
        self.baseline_seen = False
        self.results = []
        self.cache = {}

    def probe(self, probe):
        if probe.key() in self.cache:
            return self.cache[probe.key()]
        if len(self.results) >= self.budget:
            raise ProbeBudgetExhausted("probe budget of %d reached" % self.budget)
        result = self.send(probe)

        if result.outcome == ACCEPTED:
            self.baseline_seen = True
        elif (self.silent_drop and self.baseline_seen
              and result.outcome == INCONCLUSIVE and result.status is None):
            # A drop after a confirmed baseline: the weakened axis is being
            # enforced. Re-label it below-MSL, keeping the original note.
            result = ProbeResult(result.probe, BELOW_MSL, result.status,
                                 "no PoR after a confirmed baseline -- read as below-MSL on a "
                                 "card that discards below-MSL packets silently (original: %s)"
                                 % result.note)

        self.cache[probe.key()] = result
        self.results.append(result)
        return result


class ProbeBudgetExhausted(Exception):
    pass


# ---------------------------------------------------------------------------
# Task 3: find the MSL of an installed applet
# ---------------------------------------------------------------------------

class DiscoveryResult(object):
    def __init__(self):
        self.msl = None              # MslLevel, or None when it could not be pinned down
        self.thresholds = {}         # axis -> value, or None
        self.undetermined = {}       # axis -> why
        self.confirmed = False       # the confirmation probes agreed with the inference
        self.notes = []
        self.results = []

    def describe(self):
        lines = list(self.notes)
        for axis in AXES:
            value = self.thresholds.get(axis)
            if value is None:
                lines.append("%-9s : undetermined -- %s" % (axis, self.undetermined.get(axis, "")))
            else:
                lines.append("%-9s : %s" % (axis, AXIS_NAMES[axis][value]))
        if self.msl is None:
            lines.append("MSL: could not be determined from these probes")
        else:
            lines.append("MSL: %s%s" % (self.msl.describe(),
                                        "  (confirmed by check probes)" if self.confirmed
                                        else "  (NOT confirmed -- see the check probes above)"))
        return lines


def discover_msl(oracle, ceiling=None):
    """
    Find an installed applet's MSL by measuring each axis, not by assuming one.

    1. Probe the ceiling. If that is rejected with 0A, the card wants more than
       this tooling can produce and no axis can be isolated -- stop and say so
       rather than reporting a floor of "everything".
    2. For each axis, hold the other two at the ceiling and walk that axis from
       its weakest value upwards. The first value that is not rejected with 0A
       is the card's minimum on that axis.
    3. Check the answer: the inferred level itself must be accepted, and one
       notch below it on each non-zero axis must come back 0A.

    Step 3 is what separates this from a plausible guess. An applet whose MSL is
    enforced on only some axes, or whose card compares the MSL byte as a whole
    rather than field by field, fails step 3 and is reported as unconfirmed --
    with the probe log -- instead of being rounded into a tidy answer.
    """
    ceiling = ceiling or Ceiling()
    result = DiscoveryResult()

    top = ceiling.probe_at()
    top_result = oracle.probe(top)
    if top_result.outcome == BELOW_MSL:
        result.notes.append(
            "The strongest packet this tooling can build (%s) was rejected with 0A. The applet's "
            "MSL is above the reachable ceiling (%s), so the individual axes cannot be separated. "
            "Supply a KIc key for ciphering, or a stronger integrity algorithm, and run again."
            % (top.describe(), ceiling.describe()))
        result.results = oracle.results
        return result
    if top_result.outcome == INCONCLUSIVE:
        result.notes.append(
            "The strongest packet this tooling can build got no usable answer (%s). Nothing "
            "further was sent -- fix that first: check TERMINAL PROFILE was accepted, that the "
            "counter is above the card's, and that the TAR is an installed, selectable applet."
            % top_result.note)
        result.results = oracle.results
        return result

    for axis in AXES:
        limit = ceiling.axis(axis)
        found = None
        for value in range(0, limit + 1):
            probe = ceiling.probe_at(**{axis: value})
            outcome = oracle.probe(probe).outcome
            if outcome == ACCEPTED:
                found = value
                break
            if outcome == INCONCLUSIVE:
                # Do not read silence as "rejected": that would push the
                # threshold one notch too high and produce a confident wrong MSL.
                result.undetermined[axis] = ("a probe at %s got no usable answer, so the walk "
                                             "cannot be trusted past it" % AXIS_NAMES[axis][value])
                break
        if found is None and axis not in result.undetermined:
            result.undetermined[axis] = ("every value up to the ceiling (%s) was rejected with 0A"
                                         % AXIS_NAMES[axis][limit])
        result.thresholds[axis] = found

    result.results = oracle.results
    if any(result.thresholds.get(axis) is None for axis in AXES):
        return result

    result.msl = MslLevel(result.thresholds["integrity"],
                          result.thresholds["cipher"],
                          result.thresholds["counter"])
    result.confirmed = _confirm(oracle, result.msl, result.notes)
    result.results = oracle.results
    return result


def _confirm(oracle, level, notes):
    """The check probes: the level itself must pass, one notch below must not."""
    ok = True
    at_level = Probe(level.integrity, level.cipher, level.counter)
    if oracle.probe(at_level).outcome != ACCEPTED:
        notes.append("check probe: a packet built at exactly the inferred MSL was not accepted")
        ok = False
    for axis in AXES:
        value = level.axis(axis)
        if value == 0:
            continue
        below = Probe(level.integrity, level.cipher, level.counter)
        setattr(below, axis, value - 1)
        outcome = oracle.probe(below).outcome
        if outcome != BELOW_MSL:
            notes.append("check probe: lowering %s one notch below the inferred MSL was answered "
                         "%s, not 0A -- the card is not enforcing that axis the way a field-wise "
                         "MSL comparison would" % (axis, outcome))
            ok = False
    return ok


# ---------------------------------------------------------------------------
# Task 2: check that an applet's MSL is what it was installed with
# ---------------------------------------------------------------------------

class VerificationResult(object):
    def __init__(self, claimed):
        self.claimed = claimed
        self.passed = False
        self.checks = []             # (description, expected, actual, ok)
        self.results = []
        self.notes = []

    def describe(self):
        lines = list(self.notes)
        for description, expected, actual, ok in self.checks:
            lines.append("[%s] %-52s expected %-11s got %s"
                         % ("PASS" if ok else "FAIL", description, expected, actual))
        lines.append("VERDICT: the card %s enforce MSL %s"
                     % ("does" if self.passed else "does NOT demonstrably",
                        self.claimed.describe()))
        return lines


def verify_msl(oracle, claimed, ceiling=None):
    """
    Behavioural proof that a specific MSL is in force.

    Two directions, because either alone is worthless:

      not too high -- a packet built at exactly the claimed MSL must not be
                      rejected with 0A. If it is, the card wants more than was
                      asked for.
      not too low  -- for every axis the claimed MSL is above zero on, a packet
                      one notch weaker on that axis alone must be rejected with
                      0A. If it is accepted, the card is enforcing less than was
                      asked for, which is the finding that actually matters:
                      an applet reachable at a lower security level than its
                      profile claims.

    An axis the claimed MSL leaves at zero cannot be probed from below and is
    reported as such, not silently passed.
    """
    ceiling = ceiling or Ceiling()
    result = VerificationResult(claimed)

    at_level = Probe(claimed.integrity, claimed.cipher, claimed.counter)
    outcome = oracle.probe(at_level).outcome
    ok = outcome == ACCEPTED
    result.checks.append(("a packet at exactly the claimed MSL is accepted", ACCEPTED, outcome, ok))
    all_ok = ok

    for axis in AXES:
        value = claimed.axis(axis)
        if value == 0:
            result.notes.append("%s is already at its weakest value in the claimed MSL, so there "
                                "is nothing below it to probe -- this axis is untested." % axis)
            continue
        below = Probe(claimed.integrity, claimed.cipher, claimed.counter)
        setattr(below, axis, value - 1)
        outcome = oracle.probe(below).outcome
        ok = outcome == BELOW_MSL
        all_ok = all_ok and ok
        result.checks.append(("one notch below on %s is rejected with 0A" % axis,
                              BELOW_MSL, outcome, ok))

    result.passed = all_ok
    result.results = oracle.results
    return result


# ---------------------------------------------------------------------------
# A card that exists only to test the inference
# ---------------------------------------------------------------------------

class SimulatedCard(object):
    """
    An applet with a known MSL, used by selftest_msl.py to check that discovery
    recovers every one of the 32 possible levels. Optionally models the two
    behaviours that break naive probing: a card that answers a bad MAC with 01
    (which must still count as "security level accepted"), and one that stays
    silent below its MSL instead of answering 0A.
    """

    def __init__(self, msl, wrong_key=False, silent_below_msl=False):
        self.msl = msl
        self.wrong_key = wrong_key
        self.silent_below_msl = silent_below_msl
        self.sent = 0

    def __call__(self, probe):
        self.sent += 1
        if not probe.as_level().dominates(self.msl):
            if self.silent_below_msl:
                outcome, note = classify(None, False)
                return ProbeResult(probe, outcome, None, note)
            outcome, note = classify(0x0A, True)
            return ProbeResult(probe, outcome, 0x0A, note)
        status = 0x01 if self.wrong_key else 0x00
        outcome, note = classify(status, True)
        return ProbeResult(probe, outcome, status, note)
