"""
MSL checking for applets, over a plain PC/SC reader -- no UL platform, no licence.

    python tools/msl_tool.py params   --msl 12 --tar B00010
    python tools/msl_tool.py install  --msl 12 --tar B00010 --elf ... --module ... --instance ...
    python tools/msl_tool.py verify   --tar B00010 --msl 12 --kvn 01 --key <hex> --counter 1218
    python tools/msl_tool.py discover --tar B00010          --kvn 01 --key <hex> --counter 1218

The three jobs, and how each is actually done:

  install   Build INSTALL [for install and make selectable] with a TS 102 226
            toolkit parameters block carrying the MSL, and deliver it to the
            card manager (TAR 000000) inside a secured packet -- Remote
            Application Management. Card content management over OTA is
            exactly what RAM is for, and it reuses the packet builder below
            rather than needing a second, hand-rolled SCP02 implementation.
            --print-only stops after building the APDU, for feeding to whatever
            GlobalPlatform tool you already use over the contact interface.

  verify    Prove behaviourally that a claimed MSL is the one in force: a packet
            at exactly that level must not be rejected 0A, and one notch weaker
            on each axis must be.

  discover  Find the MSL of an already-installed applet by measuring each axis.
            There is no command that reads an applet's install parameters back
            off a card -- GET STATUS returns AID, life cycle and privileges, not
            parameters -- so probing is not a shortcut here, it is the only
            route.

Everything about what the answers mean lives in mslcore.py; this file is the
transport and the command line. Keys are command-line arguments, never written
to a file and never printed back.
"""
import argparse
import sys
import os
import zlib

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import mslcore as m
from mslcore import hexs, unhex

try:
    from Cryptodome.Cipher import DES3, DES, AES
    from Cryptodome.Hash import CMAC
except ImportError:                                          # pragma: no cover
    DES3 = DES = AES = CMAC = None

try:
    from smartcard.System import readers
except ImportError:                                          # pragma: no cover
    readers = None


# ---------------------------------------------------------------------------
# Crypto for the command packet
# ---------------------------------------------------------------------------

def cbc_mac(key, data, algorithm):
    """
    The cryptographic checksum over the zero-padded input, last block.

    TS 102 225 calls for DES in CBC mode; with a double- or triple-length key
    the equivalent and far easier construction to get right is a full 3DES-CBC
    pass, taking the final block. This mirrors ota_rfm.py, which is the version
    already proven against this operator's cards.
    """
    if algorithm == "aes":
        # AES integrity is CMAC (TS 102 225, KID b4b3 = 00 for AES), not a
        # CBC-MAC over zero padding. Routing it through the 3DES branch, as this
        # once did, builds a well-formed packet carrying a checksum no card can
        # match -- which comes back as status 01 and reads exactly like a wrong
        # key. Wrong for the right reason is still wrong.
        mac = CMAC.new(bytes(key), ciphermod=AES)
        mac.update(bytes(data))
        return mac.digest()[:8]

    padded = bytes(data)
    if len(padded) % 8:
        padded += b"\x00" * (8 - len(padded) % 8)
    if algorithm == "des":
        cipher = DES.new(bytes(key[:8]), DES.MODE_CBC, b"\x00" * 8)
    else:
        cipher = _des3(key)
    return cipher.encrypt(padded)[-8:]


def redundancy_check(data):
    """
    CRC32 over the same input the CC covers.

    Which CRC a card uses is coded in KID and is not always this one. That is
    survivable here on purpose: a card that dislikes the RC answers status 01
    (RC/CC/DS failed), which the classifier counts as "the packet got past the
    security-level gate" -- still a usable answer to the only question being
    asked. Never read an RC probe as proof the RC itself was right.
    """
    value = zlib.crc32(bytes(data)) & 0xFFFFFFFF
    return bytes(bytearray([(value >> 24) & 0xFF, (value >> 16) & 0xFF,
                            (value >> 8) & 0xFF, value & 0xFF]))


def encipher(key, data, algorithm):
    if algorithm == "aes":
        return AES.new(bytes(key), AES.MODE_CBC, b"\x00" * 16).encrypt(bytes(data))
    if algorithm == "des":
        cipher = DES.new(bytes(key[:8]), DES.MODE_CBC, b"\x00" * 8)
    else:
        cipher = _des3(key)
    return cipher.encrypt(bytes(data))


def _des3(key):
    """
    3DES with the degenerate-key case turned into a sentence instead of a stack
    trace: a 16-byte key whose two halves are equal IS single DES, and
    pycryptodome refuses it rather than silently weakening the cipher.
    """
    try:
        return DES3.new(bytes(key), DES3.MODE_CBC, b"\x00" * 8)
    except ValueError as error:
        raise SystemExit("this key cannot be used as 3DES (%s). A 16-byte key whose two halves "
                         "are identical is single DES -- run with --alg des, or use the real "
                         "double-length key." % error)


def block_size(algorithm):
    """Cipher block size, which is what the PCNTR padding rounds up to."""
    return 16 if algorithm == "aes" else 8


# ---------------------------------------------------------------------------
# The command packet
# ---------------------------------------------------------------------------

def build_command_packet(probe, kic, kid, tar, counter, payload, kid_key, algorithm, spi2,
                         kic_key=None):
    """
    TS 102 225 clause 5.1.1:

        CPL(2) CHL(1) SPI(2) KIc(1) KID(1) TAR(3) CNTR(5) PCNTR(1) RC/CC/DS <secured data>

    CHL counts from SPI through the end of the integrity field; CPL counts
    everything after itself, so it includes the CHL byte. The integrity value is
    computed over CPL and CHL as well -- omit those two and the card simply never
    answers, which is the classic way a home-grown builder fails.

    With ciphering on, everything from CNTR to the end is encrypted and PCNTR
    records how many padding bytes were added to make that region a whole number
    of blocks. CPL, CHL, SPI, KIc, KID and TAR always travel in the clear: the
    card needs them to know how to decrypt.

    One honest limit, and why it does not damage the answer: with ciphering on,
    whether the integrity value should cover the padding bytes as well as the
    payload is not something this tool has been able to confirm against a card,
    and the two readings give different checksums. It does not matter for what
    this tool measures. A card that dislikes the checksum answers 01, and 01
    means the packet got PAST the security-level gate -- which is the only thing
    a probe is asked to establish. The MSL verdict depends on 0A versus not-0A,
    never on the MAC being right. Do not reuse this builder for real RFM work on
    that basis; there, a wrong MAC is a wrong packet.
    """
    spi = bytes(bytearray([probe.spi_first_octet(), spi2]))
    cntr = bytes(bytearray([(counter >> (8 * i)) & 0xFF for i in range(4, -1, -1)]))
    payload = bytes(payload)

    integrity_length = {m.INTEGRITY_NONE: 0, m.INTEGRITY_RC: 4, m.INTEGRITY_CC: 8}.get(
        probe.integrity)
    if integrity_length is None:
        raise ValueError("digital signatures are not supported by this tool; "
                         "the UL platform's DefaultSCP80Security does not implement them either")

    padding = 0
    if probe.cipher == m.CIPHER_ON:
        block = block_size(algorithm)
        ciphered_length = 5 + 1 + integrity_length + len(payload)
        if ciphered_length % block:
            padding = block - (ciphered_length % block)

    chl = 2 + 1 + 1 + 3 + 5 + 1 + integrity_length
    cpl = 1 + chl + len(payload) + padding
    header = bytes(bytearray([(cpl >> 8) & 0xFF, cpl & 0xFF, chl])) + spi \
        + bytes(bytearray([kic, kid])) + bytes(tar) + cntr + bytes(bytearray([padding]))

    if kic_key is None:
        kic_key = kid_key

    if probe.integrity == m.INTEGRITY_CC:
        integrity = cbc_mac(kid_key, header + payload, algorithm)
    elif probe.integrity == m.INTEGRITY_RC:
        integrity = redundancy_check(header + payload)
    else:
        integrity = b""

    secured = cntr + bytes(bytearray([padding])) + integrity + payload + b"\x00" * padding
    if probe.cipher == m.CIPHER_ON:
        secured = encipher(kic_key, secured, algorithm)

    clear_length = 2 + 1 + 2 + 1 + 1 + 3          # CPL, CHL, SPI, KIc, KID, TAR
    return header[:clear_length] + secured


def build_envelope(command_packet, originating_address="0000000000"):
    """
    SMS-PP DOWNLOAD envelope, TS 102 223 clause 7.1.1:

        D1 <len>  82 02 83 81                device identities, network -> UICC
                  8B <len> <SMS-DELIVER TPDU>

    The high bit on 82 and 8B is the comprehension-required flag CAT TLVs carry
    (TS 101 220). Send the bare 02 and 0B instead and the envelope is accepted
    and then quietly ignored: the card answers 6200 whatever the key, TAR or
    counter, which reads exactly like a crypto failure and is not one.
    """
    user_data = [0x02, 0x70, 0x00] + list(bytearray(command_packet))
    digits = originating_address if len(originating_address) % 2 == 0 else originating_address + "F"
    address = [int(digits[i + 1] + digits[i], 16) for i in range(0, len(digits), 2)]

    tpdu = ([0x40]                                    # SMS-DELIVER, TP-UDHI set
            + [len(originating_address)] + [0x91] + address
            + [0x7F]                                  # TP-PID: SIM data download
            + [0xF6]                                  # TP-DCS: class 2, 8-bit
            + [0x00] * 7                              # TP-SCTS, not checked by the card
            + [len(user_data)] + user_data)
    body = [0x82, 0x02, 0x83, 0x81] + [0x8B, len(tpdu)] + tpdu
    return [0xD1, len(body)] + body


def parse_por(data):
    """
    TS 102 225 response packet, carried in the SMS user data:

        02 71 00                   UDH: information element 71, response packet
        RPL(2) RHL(1) TAR(3) CNTR(5) PCNTR(1) STATUS(1) CC(RHL-10) <response data>

    Walking the structure matters: scanning for a recognisable status byte finds
    the first byte of a compact response script instead, and reports a perfectly
    good PoR as a MAC failure.
    """
    data = bytearray(data)

    # RPL(2) RHL(1) TAR(3) CNTR(5) PCNTR(1) STATUS(1) = 13 bytes with no
    # integrity field and no response data. The UDH, when present, adds 3. The
    # old floor of 14 threw away exactly that shortest legal PoR -- a packet
    # answered with a bare status and nothing else, which is precisely what an
    # 0A rejection looks like on a card that sends no CC on errors.
    if len(data) < 13:
        return None
    start = 3 if data[0] == 0x02 and data[1] == 0x71 else 0
    if len(data) < start + 13:
        return None
    rhl = data[start + 2]
    body = start + 3
    parsed = {
        "tar": hexs(data[body:body + 3]),
        "counter": hexs(data[body + 3:body + 8]),
        "status": data[body + 9],
        "raw": hexs(data),
    }
    payload = data[body + 10 + max(0, rhl - 10):]
    if len(payload) >= 3:
        parsed["commands"] = payload[0]
        parsed["last_sw"] = "%02X%02X" % (payload[1], payload[2])
    return parsed


# ---------------------------------------------------------------------------
# The reader
# ---------------------------------------------------------------------------

class Reader(object):
    def __init__(self, name_hint=None):
        if readers is None:
            raise SystemExit("pyscard is not installed: pip install pyscard")
        available = readers()
        if not available:
            raise SystemExit("no PC/SC reader found")
        target = available[0]
        if name_hint:
            matches = [r for r in available if name_hint.lower() in str(r).lower()]
            if not matches:
                raise SystemExit("no reader matching %r; found: %s"
                                 % (name_hint, ", ".join(str(r) for r in available)))
            target = matches[0]
        self.name = str(target)
        self.connection = target.createConnection()
        self.connection.connect()

    def transmit(self, apdu, fetch=False):
        data, sw1, sw2 = self.connection.transmit(list(apdu))
        if sw1 == 0x6C:
            data, sw1, sw2 = self.connection.transmit(list(apdu[:-1]) + [sw2])
        guard = 0
        while sw1 == 0x61 and guard < 16:
            guard += 1
            more, sw1, sw2 = self.connection.transmit([0x00, 0xC0, 0x00, 0x00, sw2])
            data += more

        # 91 xx means the card has a proactive command waiting and is not going
        # to volunteer it: the PoR is sitting behind a FETCH. Cards differ on
        # this -- some return the response packet in the ENVELOPE response data
        # directly, which is why this is a fallback and not the only path -- but
        # without it, on a card that uses 91 xx, every probe reads as "no PoR"
        # and the whole run reports INCONCLUSIVE for a reason that has nothing
        # to do with the MSL.
        if fetch and sw1 == 0x91 and not data:
            fetched, f1, f2 = self.connection.transmit([0x80, 0x12, 0x00, 0x00, sw2])
            if f1 == 0x90 and fetched:
                return fetched, f1, f2

        return data, sw1, sw2

    def terminal_profile(self, profile):
        """
        A UICC only accepts SMS-PP DOWNLOAD once the terminal has said it
        supports it. A plain PC/SC reader never sends one, so without this the
        card's toolkit stays dormant and every envelope is ignored -- silently.
        """
        profile = list(bytearray(profile))
        _, sw1, sw2 = self.transmit([0x80, 0x10, 0x00, 0x00, len(profile)] + profile)
        return (sw1 << 8) | sw2

    def close(self):
        try:
            self.connection.disconnect()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Sending one probe
# ---------------------------------------------------------------------------

class OtaProbeSender(object):
    """
    Turns a Probe from mslcore into a real secured packet, sends it, and turns
    the PoR back into a ProbeResult.

    The payload is deliberately inert. An MSL rejection happens before the
    applet ever sees the secured data, so the probe does not need to carry
    anything meaningful -- and must not, because a TAR in the B0xxxx range is an
    RFM instance that would execute whatever APDUs it is handed, with
    administrative rights and no undo.
    """

    INERT_PAYLOAD = b"\x00"

    def __init__(self, reader, tar, kic, kid, kid_key, algorithm, counter, spi2, verbose=True,
                 payload=None, kic_key=None):
        self.reader = reader
        self.tar = bytes(tar)
        self.kic = kic
        self.kid = kid
        self.kid_key = bytes(kid_key)
        self.kic_key = self.kid_key if kic_key is None else bytes(kic_key)
        self.algorithm = algorithm
        self.counter = counter
        self.spi2 = spi2
        self.verbose = verbose
        # Overridden only by the RAM install path, which carries a real card
        # content management APDU instead of the inert probe byte.
        self.payload = self.INERT_PAYLOAD if payload is None else bytes(payload)
        self.card_counter = None

    def __call__(self, probe):
        counter = self.counter
        if probe.counter == m.COUNTER_ONE_HIGHER and self.card_counter is not None:
            counter = self.card_counter + 1

        try:
            packet = build_command_packet(probe, self.kic, self.kid, self.tar, counter,
                                          self.payload, self.kid_key, self.algorithm, self.spi2,
                                          kic_key=self.kic_key)
        except (ValueError, SystemExit) as error:
            # A probe this tool cannot build is an inconclusive probe, not a
            # rejected one. Scoring it as a rejection would push an axis
            # threshold up by one and hand back a confidently wrong MSL. The
            # Java port does the same thing for the same reason.
            outcome, note = m.classify(None, False)
            result = m.ProbeResult(probe, outcome, None,
                                   "could not be built: %s" % error)
            if self.verbose:
                print("  " + result.describe())
            return result

        envelope = build_envelope(packet)
        data, sw1, sw2 = self.reader.transmit(
            [0x80, 0xC2, 0x00, 0x00, len(envelope)] + envelope, fetch=True)
        self.counter = counter + 1

        por = parse_por(data) if data else None
        self.last_inner_sw = None
        if por is not None:
            try:
                self.card_counter = int(por["counter"], 16)
            except (KeyError, ValueError):
                pass
            # The inner SW of the executed GP command (compact PoR), so the
            # ota-install path can tell a card-manager 9000 from an error.
            self.last_inner_sw = por.get("last_sw")

        status = por["status"] if por else None
        outcome, note = m.classify(status, por is not None)
        if por is None and (sw1, sw2) != (0x90, 0x00):
            note = "%s (ENVELOPE answered %02X%02X)" % (note, sw1, sw2)
        result = m.ProbeResult(probe, outcome, status, note)
        if self.verbose:
            print("  " + result.describe())
        return result


# ---------------------------------------------------------------------------
# Command line
# ---------------------------------------------------------------------------

ALGORITHM_BITS = {"3des2": 0x5, "3des3": 0x9, "des": 0x1, "aes": 0x2}


def key_header(kvn, algorithm):
    """KIc/KID byte: key version in the high nibble, algorithm in the low."""
    return ((kvn & 0x0F) << 4) | (ALGORITHM_BITS[algorithm] & 0x0F)


def parse_msl(text):
    value = int(text, 16)
    return m.MslLevel.from_byte(value)


def build_ceiling(args, key_available):
    """
    What this run can actually build, which is not the same as what the card
    might want. Ciphering needs a KIc key; digital signatures are not
    implemented here at all.
    """
    counter = m.COUNTER_ONE_HIGHER if args.allow_one_higher else m.COUNTER_HIGHER
    cipher = m.CIPHER_ON if (key_available and args.allow_ciphering) else m.CIPHER_OFF
    return m.Ceiling(m.INTEGRITY_CC, cipher, counter)


def add_card_arguments(parser, tar_required=True):
    parser.add_argument("--tar", required=tar_required,
                        help="3-byte TAR of the applet under test, hex")
    parser.add_argument("--kvn", default="01", help="OTA key version number, hex")
    parser.add_argument("--alg", default="3des2", choices=sorted(ALGORITHM_BITS))
    # KIc (ciphering) and KID (integrity) are independent. --key sets both when
    # they are equal within a key set; --kic-key / --kid-key override either.
    parser.add_argument("--key", help="KIc=KID key value, hex (when both are equal)")
    parser.add_argument("--kic-key", dest="kic_key", help="KIc (ciphering) key, hex; overrides --key")
    parser.add_argument("--kid-key", dest="kid_key", help="KID (integrity) key, hex; overrides --key")
    parser.add_argument("--counter", required=True,
                        help="starting counter, hex -- must be ABOVE the card's stored value or "
                             "no PoR comes back at all")
    parser.add_argument("--spi2", default="09",
                        help="SPI second octet: PoR policy. 09 = PoR required over "
                             "SMS-DELIVER-REPORT")
    parser.add_argument("--profile", default="02",
                        help="TERMINAL PROFILE to send first, hex; empty to skip")
    parser.add_argument("--reader", default=None, help="substring of the reader name to use")
    parser.add_argument("--budget", type=int, default=24, help="maximum probes this run may send")
    parser.add_argument("--allow-ciphering", action="store_true",
                        help="permit probes with ciphering on (needs the KIc key to be the "
                             "ciphering key too)")
    parser.add_argument("--allow-one-higher", action="store_true",
                        help="permit probes with counter policy 'exactly one higher'; only "
                             "meaningful once a PoR has revealed the card's counter")
    parser.add_argument("--silent-drop", dest="silent_drop", action="store_true",
                        help="treat a no-PoR drop after a confirmed baseline as below-MSL "
                             "(for cards that discard below-MSL packets silently instead of "
                             "answering 0A)")


def open_sender(args):
    # KIc and KID are independent; --key sets both when they are equal.
    if not (getattr(args, "kid_key", None) or args.key):
        raise SystemExit("a KID key is required: use --kid-key, or --key for KIc=KID")
    if not (getattr(args, "kic_key", None) or args.key):
        raise SystemExit("a KIc key is required: use --kic-key, or --key for KIc=KID")
    kid_key = unhex(getattr(args, "kid_key", None) or args.key)
    kic_key = unhex(getattr(args, "kic_key", None) or args.key)
    header = key_header(int(args.kvn, 16), args.alg)
    reader = Reader(args.reader)
    print("reader      : %s" % reader.name)
    print("TAR         : %s   key set: KVN %s, %s -> KIc/KID %02X"
          % (args.tar.upper(), args.kvn.upper(), args.alg, header))
    if args.profile:
        status = reader.terminal_profile(unhex(args.profile))
        print("TERMINAL PROFILE %s -> %04X%s"
              % (args.profile.upper(), status,
                 "" if status == 0x9000 else "   <-- the toolkit may stay dormant"))
    sender = OtaProbeSender(reader, unhex(args.tar), header, header, kid_key, args.alg,
                            int(args.counter, 16), int(args.spi2, 16), kic_key=kic_key)
    return reader, sender


def command_params(args):
    """Offline: build and explain the install parameters for an MSL. No card involved."""
    toolkit = m.ToolkitParameters(parse_msl(args.msl), [unhex(t) for t in args.grant_tar],
                                  priority=int(args.priority, 16),
                                  max_timers=int(args.timers, 16),
                                  max_menu_text_length=int(args.menu_text, 16),
                                  max_channels=int(args.channels, 16))
    params = unhex(args.raw_params) if args.raw_params else m.build_install_parameters(toolkit)
    remainder = m.tlv_remainder(params)
    if remainder:
        print("REFUSED: the install parameters have %d trailing byte(s) that are not a complete "
              "TLV. A truncated block parses as 'no MSL declared', which is a legal thing for a "
              "block to say - so this would otherwise go to the card unremarked." % remainder)
        return 2
    print("install parameters: %s" % hexs(params))
    print()
    for line in m.describe_install_parameters(params):
        print(line)
    print()
    print("Read the block above against ETSI TS 102 226 clause 8.2.1.3.2 before the first")
    print("install on a card you care about -- the field ORDER is this tool's reading of that")
    print("clause, and --raw-params bypasses the builder if your profile disagrees.")
    return 0


def command_install(args):
    toolkit = m.ToolkitParameters(parse_msl(args.msl), [unhex(t) for t in args.grant_tar],
                                  priority=int(args.priority, 16),
                                  max_timers=int(args.timers, 16),
                                  max_menu_text_length=int(args.menu_text, 16),
                                  max_channels=int(args.channels, 16))
    params = unhex(args.raw_params) if args.raw_params else m.build_install_parameters(toolkit)
    remainder = m.tlv_remainder(params)
    if remainder:
        print("REFUSED: the install parameters have %d trailing byte(s) that are not a complete "
              "TLV. A truncated block parses as 'no MSL declared', which is a legal thing for a "
              "block to say - so this would otherwise go to the card unremarked." % remainder)
        return 2
    apdu = m.build_install_apdu(unhex(args.elf), unhex(args.module), unhex(args.instance), params,
                                privileges=unhex(args.privileges),
                                make_selectable=not args.no_make_selectable)

    print("install parameters: %s" % hexs(params))
    for line in m.describe_install_parameters(params):
        print("  " + line)
    print()
    print("INSTALL APDU      : %s" % hexs(apdu))
    print()

    if args.print_only:
        print("--print-only: nothing was sent. Feed the APDU above to whatever GlobalPlatform")
        print("tool you already use over the contact interface, inside a secure channel.")
        return 0

    if not args.confirm:
        print("REFUSED: installing changes the card and there is no undo. Re-run with --confirm")
        print("once the parameter dump above has been read and the AIDs are right.")
        return 1

    reader, sender = open_sender(args)
    try:
        # RAM: the same secured packet, addressed to the card manager, carrying a
        # card content management APDU instead of an inert probe byte.
        probe = m.Probe(m.INTEGRITY_CC, m.CIPHER_OFF,
                        m.COUNTER_ONE_HIGHER if args.allow_one_higher else m.COUNTER_HIGHER)
        sender.tar = unhex(args.ram_tar)
        sender.payload = apdu
        print("sending INSTALL to the card manager over RAM, TAR %s" % args.ram_tar.upper())
        result = sender(probe)
        if result.status == 0x00:
            print("PoR OK -- read the response data for the INSTALL status word before calling "
                  "this a success; PoR 00 only means the packet was accepted.")
            return 0
        print("the packet was not processed cleanly; see the status above")
        return 1
    finally:
        reader.close()


def command_verify(args):
    claimed = parse_msl(args.msl)
    reader, sender = open_sender(args)
    try:
        print("claimed MSL : %s" % claimed.describe())
        print("probing:")
        oracle = m.Oracle(sender, budget=args.budget, silent_drop=args.silent_drop)
        result = m.verify_msl(oracle, claimed, build_ceiling(args, True))
        print()
        for line in result.describe():
            print(line)
        return 0 if result.passed else 1
    finally:
        reader.close()


def command_discover(args):
    reader, sender = open_sender(args)
    try:
        ceiling = build_ceiling(args, True)
        print("reachable ceiling: %s" % ceiling.describe())
        print("probing:")
        oracle = m.Oracle(sender, budget=args.budget, silent_drop=args.silent_drop)
        try:
            result = m.discover_msl(oracle, ceiling)
        except m.ProbeBudgetExhausted as error:
            print("stopped: %s" % error)
            return 1
        print()
        for line in result.describe():
            print(line)
        return 0 if result.msl is not None else 1
    finally:
        reader.close()


def command_ota_install(args):
    """
    Load and install a CAP over OTA (RAM): wrap INSTALL [for load], the LOAD
    block chain and INSTALL [for install and make selectable] in SCP80 secured
    packets to the card manager TAR, and send them in order.

    Default is a DRY RUN - it builds and prints every packet but sends nothing.
    --confirm is required to touch the card, because installing is irreversible.
    The serialization is capload.py's, covered by selftest_capload.py.
    """
    import capload

    elf, load_apdus = capload.build_load_sequence(args.cap, block_size=args.block_size)

    # A toolkit applet carries an MSL + TAR block; a plain applet (like a payment
    # applet) installs with empty application parameters. --msl present => toolkit.
    if args.msl:
        params = m.build_install_parameters(
            m.ToolkitParameters(parse_msl(args.msl), [unhex(t) for t in (args.grant_tar or [])]))
        kind = "toolkit applet, MSL %s, TAR %s" % (args.msl, ",".join(args.grant_tar or []))
    else:
        params = m.build_install_parameters(None)   # just the mandatory empty C9
        kind = "plain applet, empty application parameters"

    install_apdu = m.build_install_apdu(
        elf, unhex(args.module), unhex(args.instance), params,
        privileges=unhex(args.privileges))

    steps = [("INSTALL [for load]", load_apdus[0])]
    steps += [("LOAD block %d" % i, a) for i, a in enumerate(load_apdus[1:])]
    steps += [("INSTALL [for install and make selectable]", install_apdu)]

    print("CAP            : %s" % args.cap)
    print("ELF / package  : %s" % hexs(elf))
    print("module AID     : %s" % args.module.upper())
    print("instance AID   : %s" % args.instance.upper())
    print("install type   : %s" % kind)
    print("card manager   : TAR %s, KVN %s, %s" % (args.tar.upper(), args.kvn.upper(), args.alg))
    print("steps          : %d secured packets" % len(steps))
    print()

    if not args.confirm:
        for name, apdu in steps:
            print("  %-42s %s" % (name, hexs(apdu)))
        print()
        print("DRY RUN: nothing was sent. Re-run with --confirm to load and install.")
        print("This is IRREVERSIBLE - prefer a disposable test card.")
        return 0

    reader, sender = open_sender(args)
    sender.tar = unhex(args.tar)
    try:
        for name, apdu in steps:
            sender.payload = apdu
            probe = m.Probe(m.INTEGRITY_CC, m.CIPHER_OFF,
                            m.COUNTER_ONE_HIGHER if args.allow_one_higher else m.COUNTER_HIGHER)
            result = sender(probe)
            if result.status is None:
                print("STOPPED at %s: no PoR (ENVELOPE drop). Counter below the card's, or the "
                      "card manager key is wrong." % name)
                return 1
            if result.status != 0x00:
                print("STOPPED at %s: PoR status %02X" % (name, result.status))
                return 1
            # the inner SW of the executed GP command, from the compact PoR
            last_sw = getattr(sender, "last_inner_sw", None)
            print("  %-42s PoR 00%s" % (name, "" if last_sw is None else ", card SW %s" % last_sw))
            if last_sw is not None and last_sw != "9000":
                print("STOPPED: the card manager answered %s to %s" % (last_sw, name))
                return 1
        print()
        print("DONE: CAP loaded and applet installed.")
        if args.grant_tar:
            print("Verify its MSL with: discover --tar %s" % args.grant_tar[0])
        return 0
    finally:
        reader.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[1],
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    subparsers = parser.add_subparsers(dest="command")

    def add_params_arguments(sub):
        sub.add_argument("--msl", required=True, help="the MSL byte, hex (e.g. 12)")
        sub.add_argument("--grant-tar", action="append", required=True, metavar="TAR",
                         help="a TAR to grant the applet in its toolkit parameters, hex; "
                              "repeatable. Distinct from --tar, which addresses a packet.")
        sub.add_argument("--priority", default="01")
        sub.add_argument("--timers", default="00")
        sub.add_argument("--menu-text", default="00")
        sub.add_argument("--channels", default="00")
        sub.add_argument("--raw-params", default=None,
                         help="use this whole install parameters field verbatim, hex, instead of "
                              "building one")

    sub = subparsers.add_parser("params", help="build and explain install parameters (no card)")
    add_params_arguments(sub)
    sub.set_defaults(func=command_params)

    sub = subparsers.add_parser("install", help="install an applet with a specific MSL")
    add_params_arguments(sub)
    sub.add_argument("--elf", required=True, help="executable load file AID, hex")
    sub.add_argument("--module", required=True, help="executable module AID, hex")
    sub.add_argument("--instance", required=True, help="application instance AID, hex")
    sub.add_argument("--privileges", default="00", help="privileges, hex (1 or 3 bytes)")
    sub.add_argument("--no-make-selectable", action="store_true",
                     help="INSTALL [for install] only -- leaves the applet unreachable by TAR")
    sub.add_argument("--ram-tar", default="000000", help="card manager TAR for RAM delivery")
    sub.add_argument("--print-only", action="store_true",
                     help="build and print the APDU, send nothing")
    sub.add_argument("--confirm", action="store_true", help="required before anything is sent")
    add_card_arguments(sub, tar_required=False)
    sub.set_defaults(func=command_install)

    sub = subparsers.add_parser("verify", help="prove a claimed MSL is the one in force")
    sub.add_argument("--msl", required=True, help="the MSL the applet is supposed to have, hex")
    add_card_arguments(sub)
    sub.set_defaults(func=command_verify)

    sub = subparsers.add_parser("discover", help="find the MSL of an installed applet")
    add_card_arguments(sub)
    sub.set_defaults(func=command_discover)

    sub = subparsers.add_parser("ota-install",
                                help="load a CAP and install it over OTA (RAM) - IRREVERSIBLE")
    sub.add_argument("--cap", required=True, help="path to the .cap file")
    sub.add_argument("--module", required=True, help="executable module AID, hex")
    sub.add_argument("--instance", required=True, help="application instance AID, hex")
    sub.add_argument("--msl", help="MSL to install, hex (toolkit applets only; omit for a plain applet)")
    sub.add_argument("--grant-tar", dest="grant_tar", action="append", metavar="TAR",
                     help="TAR to grant a toolkit applet, hex; repeatable")
    sub.add_argument("--privileges", default="00", help="privileges, hex")
    sub.add_argument("--block-size", dest="block_size", type=int, default=160,
                     help="LOAD block size (<=197 to fit one SMS-PP envelope)")
    sub.add_argument("--confirm", action="store_true",
                     help="actually send (IRREVERSIBLE); without it, a dry run")
    add_card_arguments(sub)   # --tar is the card manager TAR (000000), + key/counter
    sub.set_defaults(func=command_ota_install, tar_default="000000")

    args = parser.parse_args()
    if not getattr(args, "func", None):
        parser.print_help()
        return 2
    if args.command in ("verify", "discover") or (args.command in ("install", "ota-install")
                                                  and args.confirm
                                                  and not getattr(args, "print_only", False)):
        if DES3 is None:
            raise SystemExit("pycryptodomex is not installed: pip install pycryptodomex")
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
