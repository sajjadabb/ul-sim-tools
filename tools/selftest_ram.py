"""
End-to-end checks over the card content management jobs, against a simulated
card. No reader, no card, no UL licence.

    python tools/selftest_ram.py

Why this exists, and what it is worth:

The other self-tests check pieces -- an APDU builder here, a parser there. What
they cannot check is the thing that actually breaks: the loop. ota-install,
browse and delete each build an APDU, wrap it in a secured packet, frame an
envelope, read a PoR back, find the status word of the command INSIDE that PoR,
and decide whether to carry on. A mistake anywhere along that chain produces a
run that looks like a card problem.

So the card is simulated at the only interface that matters -- the one a reader
sees. Nothing in msl_tool.py is mocked: `pyscard` is replaced, and the real
Reader (with its 61xx GET RESPONSE chaining), the real packet builder, the real
envelope framing and the real PoR parser all run. The simulated card unwraps the
envelope, unwraps the packet, executes the APDU inside it the way a card manager
would -- including recomputing the SHA-1 of the load file it reassembled from the
LOAD chain and refusing it if the INSTALL [for load] hash does not match -- and
answers with a response packet carried behind 61xx, which is how this card
family really answers.

What this does NOT prove: that the card accepts the cryptography. The simulated
card does not verify the MAC (no authoritative test vector exists on this
machine, and inventing one would be worse than having none). It proves the
structure and the decisions, which is where the bugs are.

The Java side runs the same loop in MslScript (Sender.exchange, otaInstall,
browse, deleteObject) and cannot be run here at all: it needs the UL SDK jar.
What makes these checks evidence for it too is that both halves build identical
bytes -- selftest/MslSelfTest.java and this file's twin checks assert the same
APDUs, and the two implementations were diffed byte for byte on the same CAP.
"""
import hashlib
import io
import os
import sys
import zipfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import mslcore as m

PASSED = []
FAILED = []


def check(description, condition, detail=""):
    (PASSED if condition else FAILED).append((description, detail))
    print(("ok    " if condition else "FAIL  ") + description
          + (("  -- " + str(detail)) if (detail and not condition) else ""))


def hexs(data):
    return "".join("%02X" % b for b in bytearray(data))


# ---------------------------------------------------------------------------
# The simulated card
# ---------------------------------------------------------------------------

class SimulatedCard(object):
    """
    A card manager reachable over SMS-PP DOWNLOAD, at the reader interface.

    It unwraps what a real card unwraps and answers what a real card answers,
    including the two behaviours this card family is documented to have: the PoR
    arrives behind `61 xx` (so a GET RESPONSE is required), and a packet whose
    counter is not above the stored one is dropped silently with 6200 rather
    than refused politely.
    """

    def __init__(self, applications=None, load_files=None, counter=0,
                 por_status=0x00, drop_everything=False, omit_additional_data=False):
        # AID -> life cycle. The registry the card reports and the delete job
        # checks against.
        self.applications = dict(applications or {})
        self.load_files = dict(load_files or {})
        self.modules = {}
        self.counter = counter
        self.por_status = por_status
        self.drop_everything = drop_everything
        self.omit_additional_data = omit_additional_data

        self.envelopes = 0
        self.commands = []            # every APDU the card executed, in order
        self.deleted = []
        self.installed = []
        self.terminal_profiles = []
        self.load_file_hash = None    # from INSTALL [for load]
        self.load_blocks = b""
        self.next_block = 0
        self.load_complete = False
        self.last_tar = None

        self._pending = []            # the PoR waiting behind 61xx

    # -- the reader interface ------------------------------------------------

    def transmit(self, apdu):
        apdu = list(bytearray(apdu))

        if apdu[:2] == [0x80, 0x10]:
            self.terminal_profiles.append(bytes(bytearray(apdu[5:])))
            return [], 0x90, 0x00

        if apdu[:2] == [0x00, 0xC0]:
            length = apdu[4] or 256
            chunk, self._pending = self._pending[:length], self._pending[length:]
            return chunk, (0x61 if self._pending else 0x90), \
                (len(self._pending) if self._pending else 0x00)

        if apdu[:2] == [0x80, 0xC2]:
            self.envelopes += 1
            por = self._envelope(bytes(bytearray(apdu[5:5 + apdu[4]])))
            if por is None:
                # Silent drop: ENVELOPE 6200, no PoR. Indistinguishable from a
                # wrong key, which is the point of the hardening.
                return [], 0x62, 0x00
            self._pending = list(bytearray(por))
            return [], 0x61, len(self._pending)

        return [], 0x6D, 0x00

    # -- unwrapping ----------------------------------------------------------

    def _envelope(self, envelope):
        """D1 len 82 02 83 81 8B len <TPDU> -> the secured packet inside."""
        data = bytearray(envelope)
        assert data[0] == 0xD1, "not a D1 CAT envelope: %s" % hexs(envelope)
        assert data[2] == 0x82 and data[6] == 0x8B, \
            "device identities / TPDU tags missing their comprehension bit"

        tpdu = data[8:8 + data[7]]
        assert tpdu[0] == 0x40, "TP-UDHI is not set, so the UDH is not read"

        address_length = (tpdu[1] + 1) // 2
        pos = 2 + 1 + address_length          # TP-OA length, type of number, digits
        assert tpdu[pos] == 0x7F, "TP-PID is not SIM data download"
        assert tpdu[pos + 1] == 0xF6, "TP-DCS is not class 2, 8-bit"
        pos += 2 + 7                          # TP-DCS then TP-SCTS
        user_data = tpdu[pos + 1:pos + 1 + tpdu[pos]]
        assert bytes(user_data[:3]) == b"\x02\x70\x00", "the UDH is not a command packet"
        return self._packet(bytes(user_data[3:]))

    def _packet(self, packet):
        """
        CPL(2) CHL(1) SPI(2) KIc(1) KID(1) TAR(3) CNTR(5) PCNTR(1) CC <payload>

        The MAC is not verified: there is no authoritative vector here to check
        one against. Everything the card uses to find its way through the packet
        IS checked, because that is arithmetic and getting it wrong is the
        failure mode where a real card simply never answers.
        """
        data = bytearray(packet)
        cpl = (data[0] << 8) | data[1]
        chl = data[2]
        check_once("the packet length field counts everything after itself",
                   len(data) == 2 + cpl, "%d vs %d" % (len(data), 2 + cpl))

        integrity_length = chl - 13
        check_once("the header length field matches the integrity it declares",
                   0 <= integrity_length <= 8, "CHL=%d" % chl)

        spi1 = data[3]
        tar = bytes(data[7:10])
        counter = int(hexs(data[10:15]), 16)
        padding = data[15]
        payload = bytes(data[16 + integrity_length:2 + cpl])
        if padding:
            payload = payload[:-padding]

        self.last_tar = tar
        check_once("a RAM packet applies a cryptographic checksum",
                   (spi1 & 0x03) == m.INTEGRITY_CC, "SPI1=%02X" % spi1)

        if self.drop_everything:
            return None
        if counter <= self.counter:
            return None                       # too low: silently dropped
        self.counter = counter

        commands, status_word, response = self._command_script(payload)
        return self._response_packet(tar, commands, status_word, response)

    def _command_script(self, script):
        """
        The secured data of a RAM packet is a COMMAND SCRIPT: a sequence of
        case 3 APDUs, each CLA INS P1 P2 Lc DATA. The card walks it, executes
        each one, and reports how many it executed plus the last one's status.

        Strict on purpose, because the real card is: given a GET STATUS with a
        trailing Le byte, the MCI/Hamrah card answered "2 commands executed,
        last one 6F00". It had read that 00 as the start of another command.
        A simulator that quietly accepted the whole payload as one APDU would
        have hidden exactly the bug this reproduces.
        """
        data = bytearray(script)
        pos = 0
        executed = 0
        status, response = 0x6F00, b""

        while pos < len(data):
            if pos + 5 > len(data) or pos + 5 + data[pos + 4] > len(data):
                # A fragment that is not a whole APDU is still a command the
                # card tried to execute, and it is the LAST one - which is why
                # the answer to the real command gets thrown away.
                executed += 1
                return executed, 0x6F00, b""

            end = pos + 5 + data[pos + 4]
            status, response = self._execute(bytes(data[pos:end]))
            executed += 1
            pos = end

        return executed, status, response

    def _response_packet(self, tar, commands, status_word, response):
        """
        02 71 00 | RPL(2) RHL(1) TAR(3) CNTR(5) PCNTR(1) STATUS(1) <additional>

        The additional data is the RAM part, TS 102 226 clause 5.2: the number
        of C-APDUs executed, the status word of the last one, and its response
        data. A card that executed a command and has nothing else to say still
        sends those three bytes - which is what lets a caller tell a refused
        command inside an accepted packet from a successful one.
        """
        additional = bytes(bytearray([commands, (status_word >> 8) & 0xFF,
                                      status_word & 0xFF])) + bytes(response)
        if self.omit_additional_data:
            additional = b""

        body = bytearray(tar)
        body += bytearray(self._counter_bytes())
        body += bytearray([0x00, self.por_status])
        body += bytearray(additional)

        rhl = 10
        rpl = 1 + len(body)
        return bytes(bytearray([0x02, 0x71, 0x00, (rpl >> 8) & 0xFF, rpl & 0xFF, rhl])
                     + body)

    def _counter_bytes(self):
        value = self.counter
        return bytes(bytearray([(value >> (8 * i)) & 0xFF for i in range(4, -1, -1)]))

    # -- the card manager ----------------------------------------------------

    def _execute(self, apdu):
        """Returns (status word, response data) the way a card manager would."""
        self.commands.append(apdu)
        data = bytearray(apdu)

        if data[:2] == bytearray([0x80, 0xF2]):
            return self._get_status(data)
        if data[:2] == bytearray([0x80, 0xE4]):
            return self._delete(data)
        if data[:4] == bytearray([0x80, 0xE6, 0x02, 0x00]):
            return self._install_for_load(data)
        if data[:2] == bytearray([0x80, 0xE8]):
            return self._load(data)
        if data[:2] == bytearray([0x80, 0xE6]):
            return self._install_for_install(data)
        return 0x6D00, b""

    def _registry_bytes(self, scope):
        out = bytearray()
        if scope == m.STATUS_APPLICATIONS:
            for aid in sorted(self.applications):
                out += bytearray([len(aid)]) + bytearray(aid)
                out += bytearray([self.applications[aid], 0x00])
        elif scope == m.STATUS_LOAD_FILES_AND_MODULES:
            for aid in sorted(self.load_files):
                out += bytearray([len(aid)]) + bytearray(aid)
                out += bytearray([self.load_files[aid], 0x00])
                modules = self.modules.get(aid, [])
                out += bytearray([len(modules)])
                for module in modules:
                    out += bytearray([len(module)]) + bytearray(module)
        elif scope == m.STATUS_ISSUER_SECURITY_DOMAIN:
            isd = m.unhex("A000000151000000")
            out += bytearray([len(isd)]) + bytearray(isd) + bytearray([0x0F, 0x9E])
        return bytes(out)

    def _get_status(self, data):
        scope = data[2]
        next_occurrence = bool(data[3] & 0x01)
        aid_filter = bytes(data[7:7 + data[6]]) if data[5] == 0x4F else b""

        registry = self._registry_bytes(scope)
        if aid_filter:
            kept = bytearray()
            for entry in m.parse_registry_compact(registry, scope):
                if entry.aid == aid_filter:
                    kept += bytearray([len(entry.aid)]) + bytearray(entry.aid)
                    kept += bytearray([entry.life_cycle]) + bytearray(entry.privileges)
                    if m.scope_carries_modules(scope):
                        kept += bytearray([len(entry.modules)])
                        for module in entry.modules:
                            kept += bytearray([len(module)]) + bytearray(module)
            registry = bytes(kept)

        if not registry:
            return 0x6A88, b""

        # Split the first listing in two when there is more than one entry, so
        # the 6310 continuation is exercised rather than assumed.
        entries = m.parse_registry_compact(registry, scope)
        if len(entries) > 1 and not next_occurrence:
            first = registry[:self._first_entry_length(registry, scope)]
            self._remainder = registry[len(first):]
            return 0x6310, first
        if next_occurrence:
            return 0x9000, getattr(self, "_remainder", b"")
        return 0x9000, registry

    def _first_entry_length(self, registry, scope):
        data = bytearray(registry)
        length = 1 + data[0] + 2
        if m.scope_carries_modules(scope):
            modules = data[length]
            length += 1
            for _ in range(modules):
                length += 1 + data[length]
        return length

    def _delete(self, data):
        related = bool(data[3] & 0x80)
        # 80 E4 P1 P2 Lc | 4F <len> <AID> | Le - the tag is at 5, its length at
        # 6, the AID from 7.
        assert data[5] == 0x4F, "DELETE data is not a 4F TLV: %s" % hexs(data)
        aid = bytes(data[7:7 + data[6]])

        if aid in self.applications:
            del self.applications[aid]
            self.deleted.append(aid)
            return 0x9000, b""
        if aid in self.load_files:
            instances = [a for a in self.applications
                         if a.startswith(aid) and a != aid]
            if instances and not related:
                return 0x6985, b""
            for instance in instances:
                del self.applications[instance]
            del self.load_files[aid]
            self.deleted.append(aid)
            return 0x9000, b""
        return 0x6A88, b""

    def _install_for_load(self, data):
        pos = 5
        elf_length = data[pos]
        self._loading = bytes(data[pos + 1:pos + 1 + elf_length])
        pos += 1 + elf_length
        pos += 1 + data[pos]                      # security domain AID
        self.load_file_hash = bytes(data[pos + 1:pos + 1 + data[pos]])
        self.load_blocks = b""
        self.next_block = 0
        self.load_complete = False
        return 0x9000, b""

    def _load(self, data):
        if self.load_file_hash is None:
            return 0x6985, b""                    # no INSTALL [for load] first
        if data[3] != self.next_block:
            return 0x6A86, b""                    # block out of sequence
        self.next_block += 1
        self.load_blocks += bytes(data[5:5 + data[4]])

        if not (data[2] & 0x80):
            return 0x9000, b""

        # The last block: rebuild the load file and check it against the hash
        # the INSTALL [for load] promised, exactly as a card does. This is the
        # check that makes the whole LOAD chain mean something.
        tagged = bytearray(self.load_blocks)
        if tagged[0] != 0xC4:
            return 0x6A80, b""
        offset = 2 if tagged[1] < 0x80 else 2 + (tagged[1] & 0x7F)
        load_file = bytes(tagged[offset:])
        if hashlib.sha1(load_file).digest() != self.load_file_hash:
            return 0x6A80, b""

        self.load_files[self._loading] = 0x01
        self.load_complete = True
        return 0x9000, b""

    def _install_for_install(self, data):
        pos = 5
        fields = []
        for _ in range(4):
            fields.append(bytes(data[pos + 1:pos + 1 + data[pos]]))
            pos += 1 + data[pos]
        elf, module, instance, _privileges = fields
        parameters = bytes(data[pos + 1:pos + 1 + data[pos]])

        if elf not in self.load_files:
            return 0x6A88, b""
        if instance in self.applications:
            return 0x6985, b""

        self.applications[instance] = 0x07
        self.modules.setdefault(elf, [])
        if module not in self.modules[elf]:
            self.modules[elf].append(module)
        self.installed.append((instance, parameters))
        return 0x9000, b""


# Structural claims the simulated card makes about every packet it is sent.
# Reported once each rather than once per packet, so one broken field is one
# failure and not forty.
_once = {}


def check_once(description, condition, detail=""):
    if description in _once:
        _once[description] = _once[description] and condition
        return
    _once[description] = condition


def flush_once():
    for description in sorted(_once):
        check(description, _once[description])
    _once.clear()


# ---------------------------------------------------------------------------
# Running the real command line against it
# ---------------------------------------------------------------------------

class FakeReaderSpec(object):
    """What pyscard's readers() returns: something that makes a connection."""

    def __init__(self, card):
        self.card = card

    def __str__(self):
        return "Simulated UICC (selftest_ram)"

    def createConnection(self):
        return FakeConnection(self.card)


class FakeConnection(object):
    def __init__(self, card):
        self.card = card

    def connect(self):
        pass

    def transmit(self, apdu):
        return self.card.transmit(apdu)

    def disconnect(self):
        pass


KEY = "404142434445464748494A4B4C4D4E4F"


def run(card, argv):
    """
    Runs msl_tool's own main() against the simulated card and returns
    (exit code, printed output).

    main() is used rather than the command functions directly so the argument
    parsing, the defaults and the crypto gate are exercised too - a job that
    works only when its arguments are hand-built is a job the operator cannot
    run.
    """
    import msl_tool as t

    original_readers = t.readers
    original_argv = sys.argv
    original_stdout = sys.stdout
    t.readers = lambda: [FakeReaderSpec(card)]
    sys.argv = ["msl_tool.py"] + argv
    sys.stdout = io.StringIO()
    try:
        try:
            code = t.main()
        except SystemExit as stop:
            code = stop.code if isinstance(stop.code, int) else 1
        return code, sys.stdout.getvalue()
    finally:
        t.readers = original_readers
        sys.argv = original_argv
        sys.stdout = original_stdout


def synthetic_cap(path, elf=b"\x11\x22\x33\x44\x55", applet=b"\x11\x22\x33\x44\x55\x00",
                  method_bytes=300):
    def component(tag, payload):
        return bytes(bytearray([tag, (len(payload) >> 8) & 0xFF, len(payload) & 0xFF])) + payload

    header = b"\xDE\xCA\xFF\xED" + bytes(bytearray([1, 2, 0, 1, 5, len(elf)])) + elf
    applet_body = bytes(bytearray([1, len(applet)])) + applet + b"\x00\x11"

    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("SYN/javacard/Header.cap", component(1, header))
        archive.writestr("SYN/javacard/Directory.cap", component(2, b"\x01\x02\x03"))
        archive.writestr("SYN/javacard/Applet.cap", component(3, applet_body))
        archive.writestr("SYN/javacard/Import.cap", component(4, b"\x00"))
        archive.writestr("SYN/javacard/Method.cap", component(7, b"\xAA" * method_bytes))
        archive.writestr("SYN/javacard/Debug.cap", component(13, b"\xFF" * 50))


# ---------------------------------------------------------------------------

try:
    import msl_tool as _probe_import
    HAVE_CRYPTO = _probe_import.DES3 is not None
except ImportError:
    HAVE_CRYPTO = False

if not HAVE_CRYPTO:
    print("note: pycryptodomex is not installed, so the end-to-end RAM checks were skipped")
    print()
    print("0 passed, 0 failed")
    sys.exit(0)

USIM = m.unhex("A0000000871002FF49FF0589")
ELF = m.unhex("1122334455")
INSTANCE = m.unhex("112233445500")

# ---------------------------------------------------------------------------
# browse
# ---------------------------------------------------------------------------

print("=== browse ===")

card = SimulatedCard(applications={bytes(USIM): 0x07, bytes(INSTANCE): 0x03},
                     load_files={bytes(ELF): 0x01})
card.modules[bytes(ELF)] = [bytes(INSTANCE)]
code, out = run(card, ["browse", "--tar", "000000", "--key", KEY, "--counter", "3000000"])

check("browse exits 0 when it listed something", code == 0, out)
check("browse lists an applet instance it was never told about",
      hexs(USIM) in out, out)
check("browse names the life cycle rather than only the byte",
      "SELECTABLE" in out and "INSTALLED" in out, out)
check("browse lists the package", hexs(ELF) in out, out)
check("browse lists the module inside the package",
      "module %s" % hexs(INSTANCE) in out, out)
check("browse follows the card's 6310 continuation", "6310" in out, out)
check("browse addressed the card manager TAR", card.last_tar == b"\x00\x00\x00",
      hexs(card.last_tar or b""))
check("browse sent TERMINAL PROFILE first", card.terminal_profiles == [b"\x02"],
      str(card.terminal_profiles))
check("every browse packet was a GET STATUS and nothing else",
      all(bytearray(c)[:2] == bytearray([0x80, 0xF2]) for c in card.commands),
      str([hexs(c)[:8] for c in card.commands]))
check("browse changed nothing on the card",
      card.deleted == [] and card.installed == [] and not card.load_complete)
check("browse reports where the card's counter ended up", "counter:" in out, out)

# The bug the real card found, kept as a regression: a GET STATUS carrying its
# Le byte is TWO commands to a card that walks the script strictly, and since
# the compact response reports only the last one, the answer that mattered is
# thrown away. The MCI/Hamrah card answered exactly this: 2 commands, 6F00.
card = SimulatedCard()
with_le = m.build_get_status_apdu(m.STATUS_APPLICATIONS, b"", False, False, True)
check("a GET STATUS with Le reads as two commands, the last one 6F00",
      card._command_script(with_le) == (2, 0x6F00, b""),
      str(card._command_script(with_le)))
without_le = m.build_get_status_apdu(m.STATUS_APPLICATIONS)
# By length, not by looking at the last byte: an AID or a length field can be
# 00 itself, which is how a check like that passes while the bug is still there.
check("the default form carries no Le, so it is one command",
      len(without_le) == 5 + 2, hexs(without_le))
check("that one command is the GET STATUS itself",
      card._command_script(without_le)[0] == 1, str(card._command_script(without_le)))
check("DELETE defaults to no Le too - the same trap, the same card",
      len(m.build_delete_apdu(INSTANCE)) == 5 + 2 + len(INSTANCE),
      hexs(m.build_delete_apdu(INSTANCE)))
check("asking for Le explicitly still appends exactly one byte",
      m.build_delete_apdu(INSTANCE, False, True)
      == m.build_delete_apdu(INSTANCE) + b"\x00")


def tlv_registry(compact, scope):
    """Re-encodes a compact registry as GlobalPlatform 2.2 E3 templates."""
    out = bytearray()
    for entry in m.parse_registry_compact(compact, scope):
        body = bytearray([0x4F, len(entry.aid)]) + bytearray(entry.aid)
        if entry.life_cycle is not None:
            body += bytearray([0x9F, 0x70, 0x01, entry.life_cycle])
        if entry.privileges:
            body += bytearray([0xC5, len(entry.privileges)]) + bytearray(entry.privileges)
        for module in entry.modules:
            body += bytearray([0x84, len(module)]) + bytearray(module)
        out += bytearray([0xE3, len(body)]) + body
    return bytes(out)


class WantsTlvFormat(SimulatedCard):
    """A GlobalPlatform 2.2 card that refuses the deprecated response format."""

    def _get_status(self, data):
        if not (data[3] & 0x02):
            return 0x6A86, b""                    # incorrect P1 P2
        status, registry = SimulatedCard._get_status(self, data)
        return status, tlv_registry(registry, data[2])


card = WantsTlvFormat(applications={bytes(USIM): 0x07})
code, out = run(card, ["browse", "--tar", "000000", "--key", KEY, "--counter", "3000000",
                       "--no-packages"])
check("a card that refuses the deprecated format is not reported as empty", code == 0, out)
check("the run walks the GET STATUS forms until one is accepted",
      "6A86" in out and "trying" in out, out)
check("it says which form this card wanted", "TLV response format" in out, out)
check("and it lists the registry in that format", hexs(USIM) in out, out)
check("the accepted form is reused rather than rediscovered",
      out.count("this card wants GET STATUS") == 1, out)

card = SimulatedCard(applications={bytes(USIM): 0x07}, load_files={bytes(ELF): 0x01})
code, out = run(card, ["browse", "--tar", "000000", "--key", KEY, "--counter", "3000000",
                       "--no-packages"])
check("--no-packages asks for one scope only", hexs(ELF) not in out, out)
check("--no-packages still lists the applications", hexs(USIM) in out, out)

card = SimulatedCard(applications={bytes(USIM): 0x07}, load_files={bytes(ELF): 0x01})
code, out = run(card, ["browse", "--tar", "000000", "--key", KEY, "--counter", "3000000",
                       "--isd"])
check("--isd lists the issuer security domain and names its life cycle",
      "A000000151000000" in out and "SECURED" in out, out)

# A card whose stored counter is above the one given: every packet is dropped,
# which is exactly what a wrong key looks like. The job must say so and not
# report an empty card.
card = SimulatedCard(applications={bytes(USIM): 0x07}, counter=0x9000000)
code, out = run(card, ["browse", "--tar", "000000", "--key", KEY, "--counter", "3000000"])
check("browse with a counter below the card's exits non-zero", code != 0, out)
check("browse says the packet was not accepted rather than 'no applets'",
      "not accepted" in out, out)

# A card that answers the packet but executes nothing: PoR 00 with no
# additional data. Reported, not read as an empty registry.
card = SimulatedCard(applications={bytes(USIM): 0x07}, omit_additional_data=True)
code, out = run(card, ["browse", "--tar", "000000", "--key", KEY, "--counter", "3000000"])
check("a PoR with no response data is reported as such",
      "no response data" in out, out)

# An empty scope answers 6A88, which is an empty section and not an error.
card = SimulatedCard()
code, out = run(card, ["browse", "--tar", "000000", "--key", KEY, "--counter", "3000000"])
check("an empty registry section is reported as empty, not as a failure",
      "6A88" in out and "empty section" in out, out)
check("an empty section is not reported as an unreadable one",
      "could not be read" not in out, out)

# ---------------------------------------------------------------------------
# delete
# ---------------------------------------------------------------------------

print()
print("=== delete ===")

card = SimulatedCard(applications={bytes(INSTANCE): 0x07})
code, out = run(card, ["delete", "--aid", hexs(INSTANCE), "--tar", "000000",
                       "--key", KEY, "--counter", "3000000"])
check("delete is a dry run without --confirm", code == 0 and "DRY RUN" in out, out)
check("a dry run sends nothing at all", card.envelopes == 0, str(card.envelopes))
check("a dry run still prints the exact DELETE APDU",
      hexs(m.build_delete_apdu(INSTANCE)) in out, out)

card = SimulatedCard(applications={bytes(INSTANCE): 0x07})
code, out = run(card, ["delete", "--aid", hexs(INSTANCE), "--tar", "000000",
                       "--key", KEY, "--counter", "3000000", "--confirm"])
check("delete with --confirm exits 0", code == 0, out)
check("delete read the registry before sending", "what is at that AID now" in out, out)
check("the instance is gone from the card", bytes(INSTANCE) not in card.applications)
check("delete says so", "DONE" in out, out)
check("exactly one DELETE was sent",
      len([c for c in card.commands if bytearray(c)[:2] == bytearray([0x80, 0xE4])]) == 1,
      str([hexs(c)[:8] for c in card.commands]))

# The gate that matters most: an AID the card does not have. A DELETE for it
# can only answer 6A88, and an operator who typed one digit wrong wants to hear
# that before the send.
card = SimulatedCard(applications={bytes(USIM): 0x07})
code, out = run(card, ["delete", "--aid", "112233445501", "--tar", "000000",
                       "--key", KEY, "--counter", "3000000", "--confirm"])
check("delete refuses an AID the card does not have", code == 2 and "REFUSED" in out, out)
check("nothing was deleted", card.deleted == [], str(card.deleted))
check("no DELETE was sent at all",
      not any(bytearray(c)[:2] == bytearray([0x80, 0xE4]) for c in card.commands),
      str([hexs(c)[:8] for c in card.commands]))

# A package that still has an instance: 6985 unless the cascade is asked for.
card = SimulatedCard(applications={bytes(INSTANCE): 0x07}, load_files={bytes(ELF): 0x01})
card.modules[bytes(ELF)] = [bytes(INSTANCE)]
code, out = run(card, ["delete", "--aid", hexs(ELF), "--tar", "000000",
                       "--key", KEY, "--counter", "3000000", "--confirm"])
check("deleting a package with instances is refused by the card", code == 1, out)
check("6985 is explained as a package that still has instances",
      "6985" in out and "--related" in out, out)
check("the package is still there", bytes(ELF) in card.load_files)

card = SimulatedCard(applications={bytes(INSTANCE): 0x07}, load_files={bytes(ELF): 0x01})
card.modules[bytes(ELF)] = [bytes(INSTANCE)]
code, out = run(card, ["delete", "--aid", hexs(ELF), "--tar", "000000", "--related",
                       "--key", KEY, "--counter", "3000000", "--confirm"])
check("--related deletes the package", code == 0 and bytes(ELF) not in card.load_files, out)
check("--related took the instance with it", bytes(INSTANCE) not in card.applications)
check("the cascade is announced before it happens", "everything related to it" in out, out)

# ---------------------------------------------------------------------------
# ota-install
# ---------------------------------------------------------------------------

print()
print("=== ota-install ===")

CAP = os.path.join(os.path.dirname(os.path.abspath(__file__)), "_syn_ram.cap")
synthetic_cap(CAP)

card = SimulatedCard()
code, out = run(card, ["ota-install", "--cap", CAP, "--module", hexs(INSTANCE),
                       "--instance", hexs(INSTANCE), "--tar", "000000",
                       "--key", KEY, "--counter", "3000000"])
check("ota-install is a dry run without --confirm", code == 0 and "DRY RUN" in out, out)
check("a dry run sends nothing at all", card.envelopes == 0, str(card.envelopes))
check("a dry run prints the ELF AID it read out of the CAP", hexs(ELF) in out, out)
check("a dry run prints every packet it would send",
      out.count("80E8") >= 2 and "80E60200" in out, out)

card = SimulatedCard()
code, out = run(card, ["ota-install", "--cap", CAP, "--module", hexs(INSTANCE),
                       "--instance", hexs(INSTANCE), "--tar", "000000",
                       "--key", KEY, "--counter", "3000000", "--confirm"])
check("ota-install exits 0 against a card that accepts it", code == 0, out)
check("the card reassembled the load file and its SHA-1 matched the INSTALL [for load]",
      card.load_complete, out)
check("the package is on the card", bytes(ELF) in card.load_files)
check("the instance is on the card", bytes(INSTANCE) in card.applications)
check("the instance is SELECTABLE", card.applications.get(bytes(INSTANCE)) == 0x07)
check("ota-install reports done", "DONE" in out, out)
check("the LOAD blocks arrived in sequence order", card.next_block == len(
          [c for c in card.commands if bytearray(c)[:2] == bytearray([0x80, 0xE8])]),
      str(card.next_block))
check("every step's card status word was checked, not just the PoR",
      out.count("card SW 9000") == len(card.commands), out)

# A plain applet installs with the mandatory empty C9 and no toolkit block.
check("a plain applet was installed with empty application parameters",
      card.installed and hexs(card.installed[0][1]) == "C900",
      card.installed and hexs(card.installed[0][1]))

# A toolkit applet carries its MSL, and the card can read it back out of what
# arrived - which is the only end-to-end proof that the MSL survives the whole
# chain from the dialog to the card's own parameters block.
card = SimulatedCard()
code, out = run(card, ["ota-install", "--cap", CAP, "--module", hexs(INSTANCE),
                       "--instance", hexs(INSTANCE), "--tar", "000000",
                       "--msl", "12", "--grant-tar", "B00010",
                       "--key", KEY, "--counter", "3000000", "--confirm"])
check("a toolkit applet's install parameters arrived at the card", code == 0 and card.installed,
      out)
if card.installed:
    arrived = card.installed[0][1]
    check("the MSL the card received is the MSL that was asked for",
          m.msl_of_install_parameters(arrived) is not None
          and m.msl_of_install_parameters(arrived).to_byte() == 0x12,
          hexs(arrived))
    check("the TAR granted to the applet arrived with it",
          m.unhex("B00010") in m.parse_toolkit_parameters(
              m.find_toolkit_parameters(arrived)).tars,
          hexs(arrived))

# A card that refuses one step: the run must stop there and say which step, not
# carry on loading on top of a failure.
class RefusesInstall(SimulatedCard):
    def _install_for_install(self, data):
        return 0x6A80, b""

card = RefusesInstall()
code, out = run(card, ["ota-install", "--cap", CAP, "--module", hexs(INSTANCE),
                       "--instance", hexs(INSTANCE), "--tar", "000000",
                       "--key", KEY, "--counter", "3000000", "--confirm"])
check("a refused INSTALL stops the run with a non-zero exit", code == 1, out)
check("the refusal names the step and the status word",
      "STOPPED" in out and "6A80" in out, out)
check("the package still loaded, so the log tells the operator what to clean up",
      card.load_complete and bytes(INSTANCE) not in card.applications)

# A refused step that answers inside a good PoR is the trap this whole design is
# about: PoR 00 says the packet was fine, and only the inner status word says
# the command was not.
check("a refused command still arrived inside an accepted packet (PoR 00)",
      "PoR 00" in out, out)

# A card that accepts every packet but never says what it did with the command
# inside it. PoR 00 alone cannot distinguish a load that happened from one that
# did not, so the run must stop rather than report a success it cannot support.
synthetic_cap(CAP)
card = SimulatedCard(omit_additional_data=True)
code, out = run(card, ["ota-install", "--cap", CAP, "--module", hexs(INSTANCE),
                       "--instance", hexs(INSTANCE), "--tar", "000000",
                       "--key", KEY, "--counter", "3000000", "--confirm"])
check("a PoR with no command status word stops ota-install", code == 1, out)
check("it says the packet was accepted but the command is unconfirmed",
      "no status word" in out, out)
check("it did not claim the applet was installed", "DONE" not in out, out)
check("it stopped at the first step rather than sending the whole chain",
      card.envelopes == 1, str(card.envelopes))

# A card that drops everything: no PoR at all, which is a counter or a key, not
# a card content problem.
card = SimulatedCard(drop_everything=True)
code, out = run(card, ["ota-install", "--cap", CAP, "--module", hexs(INSTANCE),
                       "--instance", hexs(INSTANCE), "--tar", "000000",
                       "--key", KEY, "--counter", "3000000", "--confirm"])
check("a card that drops the packet stops the run", code == 1, out)
check("the drop is explained as a counter or a key, not as a load failure",
      "no PoR" in out and "counter" in out, out)

# Block size: the LOAD chain has to fit one SMS-PP envelope. A bigger CAP at a
# small block size is still delivered, in more packets.
synthetic_cap(CAP, method_bytes=900)
card = SimulatedCard()
code, out = run(card, ["ota-install", "--cap", CAP, "--module", hexs(INSTANCE),
                       "--instance", hexs(INSTANCE), "--tar", "000000",
                       "--block-size", "96",
                       "--key", KEY, "--counter", "3000000", "--confirm"])
blocks = len([c for c in card.commands if bytearray(c)[:2] == bytearray([0x80, 0xE8])])
check("a bigger CAP at a smaller block size still loads", code == 0 and card.load_complete,
      out)
check("it took more LOAD blocks to do it", blocks >= 10, str(blocks))
check("every envelope stayed within one SMS-PP packet",
      max(len(c) for c in card.commands) <= 197,
      str(max(len(c) for c in card.commands)))

try:
    os.remove(CAP)
except OSError:
    pass

print()
print("=== what the simulated card checked about every packet ===")
flush_once()

print()
print("%d passed, %d failed" % (len(PASSED), len(FAILED)))
sys.exit(1 if FAILED else 0)
