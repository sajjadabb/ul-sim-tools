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
    # The additional response data, whole: for a RAM packet that is the number
    # of executed commands, the status word of the last one, and its response
    # data (TS 102 226 clause 5.2). The browse job needs that response data --
    # a registry listing lives in it -- so it is carried rather than summarised
    # away.
    parsed["additional"] = bytes(payload)
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
        self.last_ram = None
        if por is not None:
            # The whole RAM response, for the callers that need the response
            # data and not just the status word (browse reads a registry out
            # of it).
            self.last_ram = m.parse_ram_response(por.get("additional"))
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
            # The inner SW of the executed GP command, from the compact PoR.
            # PoR 00 only says the PACKET was accepted - MAC, counter and TAR
            # all good - and says nothing about what the card manager did with
            # the command inside it. Without that status word there is nothing
            # to support a claim that the step worked, so the run stops instead
            # of loading on top of it. (MslScript does the same, for the same
            # reason.)
            last_sw = getattr(sender, "last_inner_sw", None)
            if last_sw is None:
                print("  %-42s PoR 00" % name)
                print("STOPPED at %s: the response carried no status word for the command inside "
                      "it, so this run cannot show the command itself worked." % name)
                return 1
            print("  %-42s PoR 00, card SW %s" % (name, last_sw))
            if last_sw != "9000":
                print("STOPPED: the card manager answered %s to %s" % (last_sw, name))
                return 1
        print()
        print("DONE: CAP loaded and applet installed.")
        if args.grant_tar:
            print("Verify its MSL with: discover --tar %s" % args.grant_tar[0])
        return 0
    finally:
        reader.close()


# ---------------------------------------------------------------------------
# Card content management over OTA: browse and delete
# ---------------------------------------------------------------------------

def ram_step(sender, apdu, one_higher=False):
    """
    One card content management APDU inside a secured packet to the card
    manager, and what came back.

    Returns (result, ram). Two status words matter and they are different
    things: result.status is the PoR -- 00 means the packet was accepted, MAC
    and counter and TAR all good -- while ram["sw"] is what the card manager
    did with the command inside it. A refused INSTALL arrives inside a
    perfectly good PoR 00.
    """
    sender.payload = apdu
    probe = m.Probe(m.INTEGRITY_CC, m.CIPHER_OFF,
                    m.COUNTER_ONE_HIGHER if one_higher else m.COUNTER_HIGHER)
    result = sender(probe)
    return result, getattr(sender, "last_ram", None)


def extra_commands(ram, sent=1):
    """
    The card's own evidence that an APDU carried more than one command.

    The compact RAM response counts the commands executed. More than one from a
    script carrying one means the card read trailing bytes as another command --
    which is exactly how a stray Le byte throws away the answer that mattered.
    """
    if not ram or ram.get("commands", 1) <= sent:
        return ""
    return (" -- and reported %d commands executed where %d was sent, so it read trailing "
            "bytes as another command" % (ram["commands"], sent))


def ram_get_status_once(sender, scope, aid_filter, next_occurrence, one_higher):
    """
    One GET STATUS, in a form this card will actually act on.

    Two things cards disagree about -- the trailing Le and the response format
    -- and neither can be settled from a specification. So the forms are tried
    in turn until one is accepted, and the one that worked is remembered on the
    sender for the rest of the run. A scope that is simply empty (6A88) still
    shows the form was understood, so it counts here.
    """
    chosen = getattr(sender, "status_form", None)
    if chosen is not None:
        apdu = m.build_get_status_apdu(scope, aid_filter, next_occurrence,
                                       m.status_form_is_tlv(chosen),
                                       m.status_form_has_le(chosen))
        result, ram = ram_step(sender, apdu, one_higher)
        return read_pending_data(sender, apdu, result, ram, one_higher, next_occurrence)

    result = ram = None
    for form in m.STATUS_FORMS:
        apdu = m.build_get_status_apdu(scope, aid_filter, next_occurrence,
                                       m.status_form_is_tlv(form), m.status_form_has_le(form))
        print("  trying %s: %s" % (m.status_form_label(form), hexs(apdu)))
        result, ram = ram_step(sender, apdu, one_higher)

        # A packet the card would not take says nothing about the form.
        if result.status != 0x00 or ram is None:
            return result, ram
        # 61 xx is not a refusal: the command ran and its data is waiting.
        if ram["sw"] in (0x9000, 0x6310, 0x6A88) or m.has_pending_data(ram["sw"]):
            sender.status_form = form
            print("  this card wants GET STATUS %s" % m.status_form_label(form))
            return read_pending_data(sender, apdu, result, ram, one_higher, next_occurrence)
        print("  the card answered %04X to that form%s" % (ram["sw"], extra_commands(ram)))
    return result, ram


def read_pending_data(sender, command, result, ram, one_higher, continuation=False,
                      attempts=3):
    """
    Reads data the card said was waiting, by re-sending the command with a GET
    RESPONSE after it in the same script.

    Inside a secured packet there is no transport layer to do this: the card
    manager runs the script under T=0 rules, so a command that produced data
    answers 61 xx and hands nothing over until a GET RESPONSE asks for it.
    Since the compact response format reports only the LAST command's data,
    putting the GET RESPONSE last is exactly what makes the answer come back.

    The command is repeated rather than the GET RESPONSE sent alone: no
    specification promises a card keeps its pending response between two
    secured packets, and a run that assumed it would silently read nothing.
    One retry, for the card that answers 6C yy -- "wrong length, ask for yy".
    """
    for _ in range(attempts):
        if ram is None:
            return result, ram
        length = m.pending_length(ram["sw"])
        if length < 0:
            return result, ram

        get_response = m.build_get_response_apdu(length)
        if continuation:
            # A continuation must NOT be re-sent: GET STATUS with the
            # next-occurrence bit advances the card's own cursor, so repeating
            # it walks past the bytes it just offered. The live card proved it
            # -- 615F, re-sent, then 6724 because that chunk was gone. It also
            # proved the pending response survives between packets, by carrying
            # the cursor across them.
            print("  %04X: %d byte(s) waiting - asking for them on their own, because re-sending "
                  "the command would advance the card's listing past them"
                  % (ram["sw"], length))
            result, ram = ram_step(sender, get_response, one_higher)
        else:
            print("  %04X: the card has %d byte(s) waiting, so the script is sent again with a "
                  "GET RESPONSE after the command" % (ram["sw"], length))
            result, ram = ram_step(sender, m.command_script(command, get_response), one_higher)
    return result, ram


def ram_get_status(sender, scope, aid_filter=b"", rounds=8, one_higher=False):
    """
    GET STATUS over RAM, following the card's 6310 continuations.

    6310 is "there is more, ask again with P2 next-occurrence". Each round is
    another packet and another step of the OTA counter, so the walk is bounded:
    a card that answered 6310 forever would otherwise empty the counter space.
    """
    entries = []
    next_occurrence = False

    for _ in range(rounds):
        result, ram = ram_get_status_once(sender, scope, aid_filter, next_occurrence, one_higher)

        if result.status != 0x00:
            print("  the packet was not accepted (PoR %s) -- nothing was read"
                  % ("none" if result.status is None else "%02X" % result.status))
            return entries, False
        if ram is None:
            print("  PoR 00 with no response data: this key set reaches the card manager but it "
                  "executed nothing this tool can read")
            return entries, False
        if ram["sw"] == 0x6A88:
            # An empty section, not a failure: the scope WAS read and the card
            # has nothing in it. Reporting this as unreadable would send the
            # delete job looking for a problem that is not there.
            print("  6A88: the card has nothing in this scope - an empty section, not an error")
            return entries, True
        if ram["sw"] not in (0x9000, 0x6310):
            print("  the card manager answered %04X to GET STATUS%s"
                  % (ram["sw"], extra_commands(ram)))
            print("  Every GET STATUS form this tool knows was refused. The packet WAS accepted, "
                  "so the key set reaches the card manager - this is the card refusing card "
                  "content management to it, not a transport problem.")
            return entries, False

        entries += m.parse_registry(ram["data"], scope)
        if ram["sw"] != 0x6310:
            return entries, True

        print("  6310: more entries in this scope, asking for the next ones")
        next_occurrence = True

    print("  stopped after %d continuations - the card kept saying 6310, so this listing is "
          "incomplete" % rounds)
    return entries, True


def command_browse(args):
    """
    List what is on the card: applet instances, packages and their modules.
    Read-only, over OTA (RAM).

    This is the job to run before an install or a delete. There is no command
    that reads an applet's install parameters back -- so no MSL comes out of
    here -- but GET STATUS does give the AIDs, the life cycle states and the
    module AIDs, which is what an INSTALL needs and what nobody can read off a
    CAP they do not have.
    """
    scopes = []
    if args.isd:
        scopes.append(m.STATUS_ISSUER_SECURITY_DOMAIN)
    if not args.no_applications:
        scopes.append(m.STATUS_APPLICATIONS)
    if not args.no_packages:
        scopes.append(m.STATUS_LOAD_FILES_AND_MODULES)
    if not scopes:
        raise SystemExit("nothing to list: drop one of --no-applications / --no-packages")

    reader, sender = open_sender(args)
    sender.tar = unhex(args.tar)
    applications, load_files = [], []
    total = 0
    try:
        for scope in scopes:
            print()
            print("GET STATUS - %s" % m.status_scope_label(scope))
            entries, _ = ram_get_status(sender, scope, one_higher=args.allow_one_higher)

            if entries:
                print("  " + column("AID", 34) + column("life cycle", 32) + "privileges")
                print("  " + "-" * 76)
            for entry in entries:
                print("  %s" % registry_line(entry, scope))
                for module in entry.modules:
                    print("      module  %s" % hexs(module))
                if scope == m.STATUS_APPLICATIONS:
                    applications.append(entry)
                else:
                    load_files.append(entry)
            print("  %d entr%s" % (len(entries), "y" if len(entries) == 1 else "ies"))
            total += len(entries)

        summarise_browse(applications, load_files)

        print()
        print("counter: the card's last reported value was %s - start the next run above it"
              % (sender.card_counter if sender.card_counter is None
                 else "%010X" % sender.card_counter))
        return 0 if total else 1
    finally:
        reader.close()


def column(text, width):
    """
    A table cell that keeps its gap even when the value overflows.

    A 16-byte AID is 32 characters, and the first live listing ran its AIDs
    straight into the life cycle beside them.
    """
    return text.ljust(max(width, len(text) + 2))


def registry_line(entry, scope):
    life_cycle = ("not reported" if entry.life_cycle is None
                  else "%s (%02X)" % (m.life_cycle_name(scope, entry.life_cycle),
                                      entry.life_cycle))
    return column(hexs(entry.aid), 34) + column(life_cycle, 32) \
        + (hexs(entry.privileges) if entry.privileges else "")


def summarise_browse(applications, load_files):
    """
    What the card actually holds, said once at the end.

    The per-scope tables are the evidence; this is the answer. The package each
    instance came from is a GUESS and labelled as one: an instance AID usually
    begins with its package's AID, GlobalPlatform does not require it, and
    nothing is decided on that basis.
    """
    print()
    print("=== what is on this card ===")
    selectable = sum(1 for e in applications if e.life_cycle == 0x07)
    modules = sum(len(e.modules) for e in load_files)
    print("%d applet(s) and security domain(s): %d SELECTABLE, %d not selectable"
          % (len(applications), selectable, len(applications) - selectable))
    print("%d package(s) carrying %d module(s)" % (len(load_files), modules))

    for load_file in load_files:
        print()
        print("package %s%s" % (hexs(load_file.aid),
                                "" if load_file.life_cycle is None
                                else "  (%s)" % m.life_cycle_name(m.STATUS_LOAD_FILES,
                                                                  load_file.life_cycle)))
        for module in load_file.modules:
            print("    module    %s" % hexs(module))
        for application in applications:
            if application.aid.startswith(load_file.aid) and application.aid != load_file.aid:
                print("    instance  %s  %s"
                      % (hexs(application.aid),
                         "" if application.life_cycle is None
                         else m.life_cycle_name(m.STATUS_APPLICATIONS, application.life_cycle)))

    if load_files and applications:
        print()
        print("Instances are matched to packages by AID prefix, which is a convention and not a")
        print("rule. The module AID under each package is the one an INSTALL needs.")
    print()
    print("No MSL appears above, and none can: GET STATUS returns AIDs, life cycle and")
    print("privileges, never install parameters. Run discover against an applet's TAR.")


def command_delete(args):
    """
    DELETE an applet instance or a package, over OTA (RAM). IRREVERSIBLE.

    Default is a dry run. With --confirm the registry is read first and the
    DELETE is refused when the card does not have that AID at all: a DELETE at
    a mistyped AID can only answer 6A88, and hearing that before the send is
    the point. --related is DELETE with P2 80, which for a package takes every
    instance made from it as well.
    """
    aid = unhex(args.aid)
    apdu = m.build_delete_apdu(aid, args.related)

    print("AID to delete   : %s" % hexs(aid))
    print("related objects : %s" % ("YES - the object AND everything related to it"
                                    if args.related else "no - that object only"))
    print("DELETE APDU     : %s" % hexs(apdu))
    print("card manager    : TAR %s, KVN %s, %s" % (args.tar.upper(), args.kvn.upper(), args.alg))
    print()

    if not args.confirm:
        print("DRY RUN: nothing was sent. Re-run with --confirm to delete.")
        print("This is IRREVERSIBLE - a deleted instance takes its install parameters, and so the")
        print("MSL this tool measures, with it. Prefer a disposable test card.")
        return 0

    reader, sender = open_sender(args)
    sender.tar = unhex(args.tar)
    try:
        print("what is at that AID now:")
        found = []
        for scope in (m.STATUS_APPLICATIONS, m.STATUS_LOAD_FILES_AND_MODULES):
            entries, read = ram_get_status(sender, scope, aid,
                                           one_higher=args.allow_one_higher)
            for entry in entries:
                if entry.aid == aid:
                    print("  %s" % entry.describe(scope))
                    found.append(scope)
            if not read:
                print("  the registry could not be read for %s" % m.status_scope_label(scope))

        if not found:
            print("REFUSED: %s is in neither the application nor the package registry, so a "
                  "DELETE for it can only answer 6A88. Run browse and check the AID."
                  % hexs(aid))
            return 2
        if m.STATUS_LOAD_FILES_AND_MODULES in found and not args.related:
            print("note: that AID is a package. If any instance was made from it, this DELETE is "
                  "refused unless --related is given.")

        print()
        print("sending DELETE to the card manager, TAR %s" % args.tar.upper())
        result, ram = ram_step(sender, apdu, args.allow_one_higher)

        if result.status != 0x00:
            print("the packet was not accepted (PoR %s): nothing was deleted"
                  % ("none" if result.status is None else "%02X" % result.status))
            return 1
        if ram is None:
            print("PoR 00, but no status word for the DELETE came back - browse the card to find "
                  "out whether it happened")
            return 1
        if ram["sw"] != 0x9000:
            print("the card manager answered %04X: nothing was deleted" % ram["sw"])
            if ram["sw"] == 0x6985:
                print("6985 is usually a package that still has instances (try --related) or an "
                      "applet the issuer made undeletable")
            return 1

        print("DONE: %s is gone%s" % (hexs(aid),
                                      ", with everything related to it" if args.related else ""))
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

    sub = subparsers.add_parser("browse",
                                help="list the applets and packages on the card (read-only)")
    sub.add_argument("--no-applications", dest="no_applications", action="store_true",
                     help="skip the applet instances and security domains")
    sub.add_argument("--no-packages", dest="no_packages", action="store_true",
                     help="skip the packages and their modules")
    sub.add_argument("--isd", action="store_true",
                     help="also list the issuer security domain itself and its life cycle")
    add_card_arguments(sub)   # --tar is the card manager TAR (000000)
    sub.set_defaults(func=command_browse)

    sub = subparsers.add_parser("delete",
                                help="delete an applet instance or a package - IRREVERSIBLE")
    sub.add_argument("--aid", required=True, help="the instance or package AID to delete, hex")
    sub.add_argument("--related", action="store_true",
                     help="DELETE with P2 80: the object AND everything related to it (for a "
                          "package, every instance made from it)")
    sub.add_argument("--confirm", action="store_true",
                     help="actually send (IRREVERSIBLE); without it, a dry run")
    add_card_arguments(sub)   # --tar is the card manager TAR (000000)
    sub.set_defaults(func=command_delete)

    args = parser.parse_args()
    if not getattr(args, "func", None):
        parser.print_help()
        return 2
    if args.command in ("verify", "discover", "browse") or (
            args.command in ("install", "ota-install", "delete")
            and args.confirm and not getattr(args, "print_only", False)):
        if DES3 is None:
            raise SystemExit("pycryptodomex is not installed: pip install pycryptodomex")
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
