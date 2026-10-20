"""
Card-free checks over everything in mslcore.py. No reader, no card, no UL
licence -- run it before you need any of those.

    python tools/selftest_msl.py

The parts worth having a test at all are the ones where being wrong is quiet:
an install parameters field that encodes a different MSL than the one asked
for, and an inference that returns a confident MSL from probe answers that did
not actually support it.
"""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import mslcore as m

PASSED = []
FAILED = []


def check(description, condition, detail=""):
    (PASSED if condition else FAILED).append((description, detail))
    if not condition:
        print("FAIL  %s%s" % (description, ("  -- " + detail) if detail else ""))


def all_levels():
    for integrity in range(4):
        for cipher in range(2):
            for counter in range(4):
                yield m.MslLevel(integrity, cipher, counter)


# ---------------------------------------------------------------------------
# The MSL byte
# ---------------------------------------------------------------------------

for level in all_levels():
    byte = level.to_byte()
    check("MSL %02X round-trips through to_byte/from_byte" % byte,
          m.MslLevel.from_byte(byte) == level)

check("MSL 12 decodes as the vendor spreadsheet documents it "
      "(counter higher, CC, no ciphering)",
      m.MslLevel.from_byte(0x12).integrity == m.INTEGRITY_CC
      and m.MslLevel.from_byte(0x12).cipher == m.CIPHER_OFF
      and m.MslLevel.from_byte(0x12).counter == m.COUNTER_HIGHER)


def raises(callable_, kind=ValueError):
    try:
        callable_()
    except kind:
        return True
    except Exception:
        return False
    return False


check("an MSL byte using the reserved bits b6-b8 is refused rather than silently masked",
      raises(lambda: m.MslLevel.from_byte(0x92)))
check("an empty MSL field decodes as 'no minimum enforced', not as MSL 00",
      m.MslLevel.from_field(b"") is None)
check("MSL data after the parameter byte survives a round trip",
      m.MslLevel.from_field(m.unhex("12AABB")).data == m.unhex("AABB"))

check("dominance is field-wise: CC/off/higher does not satisfy CC/on/higher",
      not m.MslLevel(2, 0, 2).dominates(m.MslLevel(2, 1, 2)))
check("dominance is field-wise: DS/on/one-higher satisfies everything",
      all(m.MslLevel(3, 1, 3).dominates(level) for level in all_levels()))


# ---------------------------------------------------------------------------
# Install parameters
# ---------------------------------------------------------------------------

for level in all_levels():
    toolkit = m.ToolkitParameters(level, [m.unhex("B00010")])
    params = m.build_install_parameters(toolkit)
    check("install parameters carrying MSL %02X read back as the same MSL" % level.to_byte(),
          m.msl_of_install_parameters(params) == level,
          m.hexs(params))

toolkit = m.ToolkitParameters(m.MslLevel(2, 0, 2),
                              [m.unhex("B00010"), m.unhex("B00011")],
                              priority=0x02, max_timers=0x01,
                              max_menu_text_length=0x10,
                              menu_entries=[m.MenuEntry(0x01, 0x02), m.MenuEntry(0x00, 0x00)],
                              max_channels=0x02)
params = m.build_install_parameters(toolkit)
parsed = m.parse_toolkit_parameters(m.find_toolkit_parameters(params))
check("menu entries do not shift the MSL field out of place",
      parsed.msl == m.MslLevel(2, 0, 2), m.hexs(params))
check("both TARs survive a round trip",
      [m.hexs(t) for t in parsed.tars] == ["B00010", "B00011"])
check("the other toolkit fields survive a round trip",
      parsed.priority == 0x02 and parsed.max_timers == 0x01
      and parsed.max_menu_text_length == 0x10 and parsed.max_channels == 0x02
      and len(parsed.menu_entries) == 2)

check("C9 is emitted even when empty, because GlobalPlatform requires the tag",
      m.hexs(m.build_install_parameters(toolkit)).startswith("C900"))
check("an applet installed with no MSL field reads back as 'no minimum'",
      m.msl_of_install_parameters(
          m.build_install_parameters(m.ToolkitParameters(None, [m.unhex("B00010")]))) is None)
check("install parameters with no toolkit block at all read back as 'no minimum'",
      m.msl_of_install_parameters(m.unhex("C900")) is None)

check("a truncated toolkit block raises instead of returning a half-parsed MSL",
      raises(lambda: m.parse_toolkit_parameters(m.unhex("010000000001"))))
check("a TAR field length that is not a multiple of 3 raises",
      raises(lambda: m.parse_toolkit_parameters(m.unhex("01000000000112020000"))))

# The two ETSI install-parameter formats (clause 8.2.1.3.2, confirmed from the
# spec PDF): UICC is EA{80}, SIM is EF{CA}. EA{CA} is the malformed cross the
# card rejects with 6A80, so the builder must never emit it.
_tk = m.ToolkitParameters(m.MslLevel.from_byte(0x12), [m.unhex("B00011")])
_uicc = m.build_install_parameters(_tk, fmt=m.FORMAT_UICC)
_sim = m.build_install_parameters(_tk, fmt=m.FORMAT_SIM)
check("UICC format wraps toolkit tag 80 in EA",
      _uicc == m.unhex("C900EA0D800B0100000000011203B00011"), m.hexs(_uicc))
check("SIM format wraps toolkit tag CA in EF",
      _sim == m.unhex("C900EF0DCA0B0100000000011203B00011"), m.hexs(_sim))
check("the builder never emits the EA{CA} cross the card rejects",
      m.hexs(_uicc).find("EA0DCA") < 0 and m.hexs(_sim).find("EACA") < 0)
check("UICC format reads back its MSL", m.msl_of_install_parameters(_uicc) == m.MslLevel(2, 0, 2))
check("SIM format reads back its MSL", m.msl_of_install_parameters(_sim) == m.MslLevel(2, 0, 2))
check("the default format is UICC (EA{80})",
      m.build_install_parameters(_tk) == _uicc)

# The MSL must be readable out of a field built by some other tool, in which the
# EA block may not be first and may carry siblings.
foreign = m.unhex("C900EF04C602000A") + m.unhex("EA0DCA0B0100000000011203B00010")
check("the MSL is found even when EA is not the first tag",
      m.msl_of_install_parameters(foreign) == m.MslLevel(2, 0, 2))


# ---------------------------------------------------------------------------
# The INSTALL APDU
# ---------------------------------------------------------------------------

apdu = m.build_install_apdu(m.unhex("A00000015100"), m.unhex("A0000001510001"),
                            m.unhex("A0000001510001"), params)
check("INSTALL is 80 E6 0C 00", m.hexs(apdu).startswith("80E60C00"))
check("Lc matches the data that follows it", apdu[4] == len(apdu) - 5, m.hexs(apdu))
check("[for install] without make-selectable is P1=04",
      m.hexs(m.build_install_apdu(m.unhex("A0"), m.unhex("A0"), m.unhex("A0"), params,
                                  make_selectable=False)).startswith("80E60400"))
fields = []
pos = 5
while pos < len(apdu):
    length = apdu[pos]
    fields.append(apdu[pos + 1:pos + 1 + length])
    pos += 1 + length
check("INSTALL data is exactly six length-prefixed fields", len(fields) == 6 and pos == len(apdu),
      "%d fields, ended at %d of %d" % (len(fields), pos, len(apdu)))
check("the fifth field is the install parameters", fields[4] == params)


# ---------------------------------------------------------------------------
# Classifying a PoR
# ---------------------------------------------------------------------------

check("status 0A is the only one that means 'below the MSL'",
      m.classify(0x0A, True)[0] == m.BELOW_MSL)
check("a MAC failure (01) counts as 'security level accepted', because the MSL "
      "check happens first",
      m.classify(0x01, True)[0] == m.ACCEPTED)
check("counter low (02) counts as 'security level accepted' for the same reason",
      m.classify(0x02, True)[0] == m.ACCEPTED)
check("no PoR is inconclusive, never 'accepted'", m.classify(None, False)[0] == m.INCONCLUSIVE)
check("TAR unknown (09) is inconclusive -- no applet means no MSL",
      m.classify(0x09, True)[0] == m.INCONCLUSIVE)


# ---------------------------------------------------------------------------
# Discovery: recover every possible MSL
# ---------------------------------------------------------------------------

full = m.Ceiling(m.INTEGRITY_DS, m.CIPHER_ON, m.COUNTER_ONE_HIGHER)

worst_probes = 0
for level in all_levels():
    card = m.SimulatedCard(level)
    result = m.discover_msl(m.Oracle(card), full)
    worst_probes = max(worst_probes, card.sent)
    check("discovery recovers MSL %02X" % level.to_byte(),
          result.msl == level and result.confirmed,
          "got %s in %d probes" % (result.msl and result.msl.describe(), card.sent))
check("discovery of any MSL costs at most 12 probes", worst_probes <= 12,
      "worst case was %d" % worst_probes)

# The regression that matters most: a wrong OTA key must not turn into a wrong MSL.
for level in all_levels():
    card = m.SimulatedCard(level, wrong_key=True)
    result = m.discover_msl(m.Oracle(card), full)
    check("discovery still recovers MSL %02X when every accepted packet fails its MAC"
          % level.to_byte(),
          result.msl == level, "got %s" % (result.msl and result.msl.describe()))

# A card that goes silent below its MSL must produce "undetermined", not a guess,
# WITHOUT silent-drop mode -- a drop is ambiguous and must not be read as 0A.
card = m.SimulatedCard(m.MslLevel(2, 0, 2), silent_below_msl=True)
result = m.discover_msl(m.Oracle(card), full)
check("a card that stays silent below its MSL yields 'undetermined' without silent-drop mode",
      result.msl is None and result.undetermined)

# WITH silent-drop mode, the same card is fully mapped: every one of the 32 MSL
# values is recovered from drops read as below-MSL after a confirmed baseline.
for level in all_levels():
    card = m.SimulatedCard(level, silent_below_msl=True)
    result = m.discover_msl(m.Oracle(card, silent_drop=True), full)
    check("silent-drop mode recovers MSL %02X from a card that drops below-MSL silently"
          % level.to_byte(),
          result.msl == level and result.confirmed,
          "got %s" % (result.msl and result.msl.describe()))

# Silent-drop plus a wrong key (every accepted probe answers 01, every below-MSL
# one drops) must still recover the level -- the card on the bench behaves this way.
for level in all_levels():
    card = m.SimulatedCard(level, wrong_key=True, silent_below_msl=True)
    result = m.discover_msl(m.Oracle(card, silent_drop=True), full)
    check("silent-drop + bad-MAC still recovers MSL %02X" % level.to_byte(),
          result.msl == level, "got %s" % (result.msl and result.msl.describe()))

# Safety: silent-drop must NOT fabricate a level when even the ceiling drops
# (no baseline) -- a dead/wrong-key/wrong-counter card still yields undetermined.
class _AlwaysSilent(object):
    sent = 0
    def __call__(self, probe):
        self.sent += 1
        outcome, note = m.classify(None, False)
        return m.ProbeResult(probe, outcome, None, note)
result = m.discover_msl(m.Oracle(_AlwaysSilent(), silent_drop=True), full)
check("silent-drop still yields 'undetermined' when even the ceiling gets no PoR",
      result.msl is None)

# An MSL above what the tooling can build must be reported as such.
card = m.SimulatedCard(m.MslLevel(m.INTEGRITY_CC, m.CIPHER_ON, m.COUNTER_HIGHER))
result = m.discover_msl(m.Oracle(card), m.Ceiling(m.INTEGRITY_CC, m.CIPHER_OFF, m.COUNTER_HIGHER))
check("an MSL above the reachable ceiling is reported as out of reach, not as 'rejects everything'",
      result.msl is None and any("above the reachable ceiling" in note for note in result.notes))
check("nothing further is sent once the ceiling probe is rejected",
      card.sent == 1, "sent %d" % card.sent)

# The probe budget is a real stop, not decoration.
card = m.SimulatedCard(m.MslLevel(3, 1, 3))
check("the probe budget stops the run instead of walking every axis",
      raises(lambda: m.discover_msl(m.Oracle(card, budget=2), full), m.ProbeBudgetExhausted))


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------

claimed = m.MslLevel(m.INTEGRITY_CC, m.CIPHER_OFF, m.COUNTER_HIGHER)

result = m.verify_msl(m.Oracle(m.SimulatedCard(claimed)), claimed, full)
check("verification passes when the card enforces exactly the claimed MSL", result.passed)

weaker = m.MslLevel(m.INTEGRITY_CC, m.CIPHER_OFF, m.COUNTER_NO_CHECK)
result = m.verify_msl(m.Oracle(m.SimulatedCard(weaker)), claimed, full)
check("verification fails when the card enforces LESS than claimed -- the finding that matters",
      not result.passed)

stronger = m.MslLevel(m.INTEGRITY_CC, m.CIPHER_ON, m.COUNTER_HIGHER)
result = m.verify_msl(m.Oracle(m.SimulatedCard(stronger)), claimed, full)
check("verification fails when the card enforces MORE than claimed", not result.passed)

result = m.verify_msl(m.Oracle(m.SimulatedCard(m.MslLevel(0, 0, 0))), m.MslLevel(0, 0, 0), full)
check("a claimed MSL of 00 reports every axis as untested rather than passing vacuously",
      len(result.notes) == 3)


# ---------------------------------------------------------------------------
# The strict TLV check that guards a pasted install parameters block
# ---------------------------------------------------------------------------

check("a well-formed parameters field has no remainder",
      m.tlv_remainder(m.unhex("C900EA0D800B0100000000011203B00010")) == 0)
check("a tag with no length byte is a remainder of 1",
      m.tlv_remainder(m.unhex("C9")) == 1)
check("a length that overruns the buffer leaves the rest unconsumed",
      m.tlv_remainder(m.unhex("C90A0011")) == 4,
      str(m.tlv_remainder(m.unhex("C90A0011"))))
check("trailing junk after a good TLV is caught",
      m.tlv_remainder(m.unhex("C900FF")) == 1)
check("an empty field is well formed", m.tlv_remainder(b"") == 0)
check("the tolerant walk still parses a truncated block to 'no MSL' - which is exactly why "
      "the remainder check has to exist",
      m.msl_of_install_parameters(m.unhex("C9")) is None)


# ---------------------------------------------------------------------------
# GET STATUS, DELETE, and what a RAM packet answers
#
# The twins of the same checks in selftest/MslSelfTest.java. Both sides are
# diffed against each other on the same inputs, which is the only thing that
# makes "ports of each other" mean anything: a card content management APDU
# built one way here and another way there is a card that behaves differently
# depending on which half of the tool reached it.
# ---------------------------------------------------------------------------

check("GET STATUS for applications is 80 F2 40 00 02 4F 00 00",
      m.hexs(m.build_get_status_apdu(m.STATUS_APPLICATIONS)) == "80F24000024F0000",
      m.hexs(m.build_get_status_apdu(m.STATUS_APPLICATIONS)))
check("an AID filter goes in tag 4F",
      m.hexs(m.build_get_status_apdu(m.STATUS_APPLICATIONS, m.unhex("A000000009")))
      == "80F24000074F05A00000000900")
check("the next-occurrence continuation sets P2 bit b1",
      bytearray(m.build_get_status_apdu(m.STATUS_APPLICATIONS, b"", True))[3] == 0x01)
check("asking for the TLV response format sets P2 bit b2",
      bytearray(m.build_get_status_apdu(m.STATUS_APPLICATIONS, b"", False, True))[3] == 0x02)
check("the load-file scope asks for modules too (P1 10)",
      m.scope_carries_modules(m.STATUS_LOAD_FILES_AND_MODULES)
      and not m.scope_carries_modules(m.STATUS_LOAD_FILES))

check("DELETE of an instance is 80 E4 00 00, tag 4F, Le 00",
      m.hexs(m.build_delete_apdu(m.unhex("A000000009000102")))
      == "80E400000A4F08A00000000900010200",
      m.hexs(m.build_delete_apdu(m.unhex("A000000009000102"))))
check("DELETE with related objects sets P2 to 80 - the cascade, not a different command",
      bytearray(m.build_delete_apdu(m.unhex("A000000009"), True))[3] == 0x80)
check("DELETE refuses an AID too short to be one",
      raises(lambda: m.build_delete_apdu(m.unhex("A0000000"))))

# PoR 00 is about the packet; the inner status word is about the command. A run
# that reads only the first reports a refused INSTALL as a successful one.
check("a RAM response shorter than a status word reads as none at all",
      m.parse_ram_response(m.unhex("0190")) is None and m.parse_ram_response(None) is None)
_ram = m.parse_ram_response(m.unhex("019000"))
check("a RAM response reads the command count and the status word",
      _ram is not None and _ram["commands"] == 1 and _ram["sw"] == 0x9000)
_ram = m.parse_ram_response(m.unhex("016A80"))
check("a refused command inside an accepted packet carries its own status word",
      _ram is not None and _ram["sw"] == 0x6A80)
_ram = m.parse_ram_response(m.unhex("0190000102030405"))
check("the response data of the last command follows the status word",
      _ram is not None and m.hexs(_ram["data"]) == "0102030405")

_entries = m.parse_registry_compact(m.unhex("08A0000000090001020700"
                                            "05A00000000900" "0300"),
                                    m.STATUS_APPLICATIONS)
check("the compact registry format reads every entry", len(_entries) == 2, str(len(_entries)))
check("the first entry's AID is read whole",
      _entries and m.hexs(_entries[0].aid) == "A000000009000102")
check("life cycle 07 is SELECTABLE",
      _entries and _entries[0].life_cycle == 0x07
      and m.life_cycle_name(m.STATUS_APPLICATIONS, 0x07) == "SELECTABLE")
check("life cycle 03 is INSTALLED but not selectable",
      m.life_cycle_name(m.STATUS_APPLICATIONS, 0x03) == "INSTALLED")
check("the locked bit is reported as LOCKED whatever the rest of the byte says",
      m.life_cycle_name(m.STATUS_APPLICATIONS, 0x83) == "LOCKED")
check("a load file's 01 is LOADED, not OP_READY",
      m.life_cycle_name(m.STATUS_LOAD_FILES, 0x01) == "LOADED"
      and m.life_cycle_name(m.STATUS_ISSUER_SECURITY_DOMAIN, 0x01) == "OP_READY")

_modules = m.parse_registry_compact(m.unhex("05A000000009" "0100" "01" "07A0000000090001"),
                                    m.STATUS_LOAD_FILES_AND_MODULES)
check("a load file entry carries its modules",
      len(_modules) == 1 and len(_modules[0].modules) == 1, str(len(_modules)))
check("the module AID is read out of the module list",
      _modules and m.hexs(_modules[0].modules[0]) == "A0000000090001")

# E3 11 { 4F 08 <AID>  9F70 01 07  C5 01 00 } - 17 bytes of template.
_tlv = m.parse_registry(m.unhex("E311" "4F08A000000009000102" "9F700107" "C50100"),
                        m.STATUS_APPLICATIONS)
check("the TLV registry format is recognised from its E3 template", len(_tlv) == 1,
      str(len(_tlv)))
check("the TLV entry's AID comes from tag 4F",
      _tlv and m.hexs(_tlv[0].aid) == "A000000009000102")
check("the TLV entry's life cycle comes from tag 9F70, a two-byte tag",
      _tlv and _tlv[0].life_cycle == 0x07)
check("the TLV entry's privileges come from tag C5",
      _tlv and m.hexs(_tlv[0].privileges) == "00")

check("a truncated registry stops rather than inventing an entry",
      m.parse_registry_compact(m.unhex("08A000"), m.STATUS_APPLICATIONS) == [])
check("an empty registry response is no entries, not an error",
      m.parse_registry(b"", m.STATUS_APPLICATIONS) == []
      and m.parse_registry(None, m.STATUS_APPLICATIONS) == [])


# ---------------------------------------------------------------------------
# The packet builder in msl_tool.py
#
# These are structural checks, not crypto vectors: there is no authoritative
# test vector on this machine to check a real CC against, and inventing one
# would be worse than having none. What CAN be checked without a card is that
# the lengths the card uses to find its way through the packet are right --
# CPL, CHL and the PCNTR padding -- because those are arithmetic, and getting
# them wrong is the failure mode where the card simply never answers.
# ---------------------------------------------------------------------------

try:
    import msl_tool as t
    HAVE_CRYPTO = t.DES3 is not None
except ImportError:
    HAVE_CRYPTO = False

if not HAVE_CRYPTO:
    print("note: pycryptodomex is not installed, so the packet builder checks were skipped")
else:
    KEY16 = bytes(bytearray(range(16)))
    TAR = m.unhex("B00010")

    for integrity, integrity_length in ((m.INTEGRITY_NONE, 0),
                                        (m.INTEGRITY_RC, 4),
                                        (m.INTEGRITY_CC, 8)):
        for cipher in (m.CIPHER_OFF, m.CIPHER_ON):
            for payload_length in (1, 7, 8, 9, 16):
                probe = m.Probe(integrity, cipher, m.COUNTER_HIGHER)
                payload = bytes(bytearray(payload_length))
                packet = t.build_command_packet(probe, 0x15, 0x15, TAR, 0x1000,
                                                payload, KEY16, "3des2", 0x09)
                label = "integrity %d, cipher %d, %d-byte payload" % (
                    integrity, cipher, payload_length)

                cpl = (packet[0] << 8) | packet[1]
                chl = packet[2]

                check("CPL counts every byte after itself (%s)" % label,
                      cpl == len(packet) - 2,
                      "CPL says %d, packet has %d after CPL" % (cpl, len(packet) - 2))
                check("CHL runs from SPI through the integrity field (%s)" % label,
                      chl == 13 + integrity_length,
                      "CHL is %d, expected %d" % (chl, 13 + integrity_length))

                if cipher == m.CIPHER_ON:
                    # Only CPL(2) CHL(1) SPI(2) KIc(1) KID(1) TAR(3) travel in
                    # the clear -- 10 bytes. Everything from CNTR on is ciphered.
                    ciphered = len(packet) - 10
                    check("the ciphered region is a whole number of blocks (%s)" % label,
                          ciphered % 8 == 0, "%d bytes" % ciphered)
                else:
                    # PCNTR sits after CPL CHL SPI KIc KID TAR CNTR = 15 bytes.
                    check("PCNTR is zero when nothing is ciphered (%s)" % label,
                          packet[15] == 0, "PCNTR is %02X" % packet[15])
                    check("the packet is header plus integrity plus payload (%s)" % label,
                          len(packet) == 16 + integrity_length + payload_length,
                          "%d bytes" % len(packet))

    # A digital-signature probe must refuse to build rather than emit something
    # shaped like a packet: the SDK does not implement DS either.
    try:
        t.build_command_packet(m.Probe(m.INTEGRITY_DS, m.CIPHER_OFF, m.COUNTER_HIGHER),
                               0x15, 0x15, TAR, 0x1000, b"\x00", KEY16, "3des2", 0x09)
        check("a digital-signature probe is refused, not silently mis-built", False)
    except ValueError:
        check("a digital-signature probe is refused, not silently mis-built", True)

    # AES must not quietly come out of the 3DES branch.
    aes_mac = t.cbc_mac(KEY16, b"abcdefgh", "aes")
    des_mac = t.cbc_mac(KEY16, b"abcdefgh", "3des2")
    check("an AES key set produces a CMAC, not a 3DES CBC-MAC", aes_mac != des_mac)
    check("the AES checksum is 8 bytes like the others", len(aes_mac) == 8)
    check("AES pads to 16-byte blocks, DES families to 8",
          t.block_size("aes") == 16 and t.block_size("3des2") == 8)

    aes_packet = t.build_command_packet(
        m.Probe(m.INTEGRITY_CC, m.CIPHER_ON, m.COUNTER_HIGHER),
        0x25, 0x25, TAR, 0x1000, b"\x00", KEY16, "aes", 0x09)
    check("an AES ciphered packet is a whole number of 16-byte blocks",
          (len(aes_packet) - 10) % 16 == 0, "%d ciphered bytes" % (len(aes_packet) - 10))

    # The PoR floor: 13 bytes is a legal packet, 12 is not.
    minimal = m.unhex("000A" + "0A" + "B00010" + "0000001000" + "00" + "0A")
    parsed = t.parse_por(minimal)
    check("the shortest legal PoR (13 bytes, no CC, no data) parses",
          parsed is not None and parsed["status"] == 0x0A,
          "got %r" % (parsed,))
    check("a 12-byte fragment is refused rather than half-parsed",
          t.parse_por(minimal[:12]) is None)

    with_udh = m.unhex("027100") + minimal
    parsed = t.parse_por(with_udh)
    check("a PoR behind its UDH parses to the same status",
          parsed is not None and parsed["status"] == 0x0A)
    check("the PoR counter is read from the right offset",
          parsed is not None and parsed["counter"] == "0000001000",
          "got %r" % (parsed and parsed["counter"],))

    # The envelope framing that fails silently when it is wrong.
    envelope = t.build_envelope(b"\x01\x02\x03")
    check("the envelope is a D1 CAT TLV", envelope[0] == 0xD1)
    check("device identities carry the comprehension-required bit (82, not 02)",
          envelope[2] == 0x82)
    check("the SMS TPDU tag carries it too (8B, not 0B)", 0x8B in envelope)
    check("the envelope length byte matches what follows",
          envelope[1] == len(envelope) - 2)


# ---------------------------------------------------------------------------

print()
print("%d passed, %d failed" % (len(PASSED), len(FAILED)))
sys.exit(1 if FAILED else 0)
