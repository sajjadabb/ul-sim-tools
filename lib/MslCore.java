import java.util.ArrayList;
import java.util.List;

/**
 * The MSL logic: nothing in this file touches a card, a reader or the SDK.
 *
 * This is the Java port of tools/mslcore.py, class for class and method for
 * method, so the normal-mode tool and the UL scripts can be diffed against each
 * other instead of drifting apart. selftest/MslSelfTest.java runs the same
 * checks as tools/selftest_msl.py.
 *
 * Governing specs:
 *   ETSI TS 102 225 clause 5.1.1 - secured packet structure and SPI coding
 *   ETSI TS 102 226 clause 8.2.1.3.2 - UICC toolkit application specific
 *                                      parameters, which is where the MSL lives
 *   GlobalPlatform Card Specification 2.2 clause 11.5 - INSTALL
 *
 * What MSL is, in one paragraph, because everything else follows from it: an
 * applet on a UICC carries a Minimum Security Level fixed at install time in
 * its install parameters. When a secured packet arrives for that applet's TAR,
 * the card compares the security the packet actually applied (the SPI first
 * octet) against the MSL and rejects it with response status 0A - insufficient
 * security level - BEFORE checking the MAC or the counter. That ordering is
 * what makes MSL testable: 0A is an answer no wrong key and no stale counter
 * can produce.
 */
public final class MslCore
{
    private MslCore() { }

    // ------------------------------------------------------------------
    // The three axes of the MSL byte / SPI first octet (TS 102 225, 5.1.1)
    //   b2 b1  integrity     b3  ciphering     b5 b4  counter policy
    // ------------------------------------------------------------------

    public static final int INTEGRITY_NONE = 0;
    public static final int INTEGRITY_RC = 1;
    public static final int INTEGRITY_CC = 2;
    public static final int INTEGRITY_DS = 3;

    public static final int CIPHER_OFF = 0;
    public static final int CIPHER_ON = 1;

    public static final int COUNTER_NONE = 0;
    public static final int COUNTER_NO_CHECK = 1;
    public static final int COUNTER_HIGHER = 2;
    public static final int COUNTER_ONE_HIGHER = 3;

    public static final int AXIS_INTEGRITY = 0;
    public static final int AXIS_CIPHER = 1;
    public static final int AXIS_COUNTER = 2;
    public static final int[] AXES = { AXIS_INTEGRITY, AXIS_CIPHER, AXIS_COUNTER };

    private static final String[] INTEGRITY_NAMES = {
        "no integrity", "redundancy check", "cryptographic checksum", "digital signature" };
    private static final String[] CIPHER_NAMES = { "no ciphering", "ciphering" };
    private static final String[] COUNTER_NAMES = {
        "no counter", "counter present, not checked",
        "counter must be higher", "counter must be exactly one higher" };
    private static final String[] AXIS_LABELS = { "integrity", "cipher", "counter" };

    public static String axisLabel(int axis)       { return AXIS_LABELS[axis]; }
    public static int axisMaximum(int axis)        { return axis == AXIS_CIPHER ? 1 : 3; }

    public static String axisValueName(int axis, int value)
    {
        if (axis == AXIS_INTEGRITY) { return INTEGRITY_NAMES[value]; }
        if (axis == AXIS_CIPHER)    { return CIPHER_NAMES[value]; }
        return COUNTER_NAMES[value];
    }

    /** The SPI first octet for a packet built at this security - same coding as the MSL byte. */
    public static int spiFirstOctet(int integrity, int cipher, int counter)
    {
        return (integrity & 0x03) | ((cipher & 0x01) << 2) | ((counter & 0x03) << 3);
    }

    // ------------------------------------------------------------------
    // Hex
    // ------------------------------------------------------------------

    public static String hex(byte[] data)
    {
        if (data == null) { return ""; }

        StringBuilder text = new StringBuilder(data.length * 2);
        for (int i = 0; i < data.length; i++)
        {
            text.append(String.format("%02X", new Object[] { Integer.valueOf(data[i] & 0xFF) }));
        }
        return text.toString();
    }

    public static String hexByte(int value)
    {
        return String.format("%02X", new Object[] { Integer.valueOf(value & 0xFF) });
    }

    /** Parses hex, ignoring spaces and colons. Throws IllegalArgumentException on anything else. */
    public static byte[] unhex(String text)
    {
        if (text == null) { return new byte[0]; }

        StringBuilder cleaned = new StringBuilder();
        for (int i = 0; i < text.length(); i++)
        {
            char c = text.charAt(i);
            if (c == ' ' || c == ':' || c == '\t' || c == '\n' || c == '\r') { continue; }
            cleaned.append(c);
        }
        String digits = cleaned.toString();
        if ((digits.length() % 2) != 0)
        {
            throw new IllegalArgumentException("odd number of hex digits: " + text);
        }

        byte[] out = new byte[digits.length() / 2];
        for (int i = 0; i < out.length; i++)
        {
            try
            {
                out[i] = (byte) Integer.parseInt(digits.substring(i * 2, i * 2 + 2), 16);
            }
            catch (NumberFormatException e)
            {
                throw new IllegalArgumentException("not hex: " + text);
            }
        }
        return out;
    }

    public static boolean equal(byte[] a, byte[] b)
    {
        if (a == null || b == null) { return a == b; }
        if (a.length != b.length) { return false; }
        for (int i = 0; i < a.length; i++) { if (a[i] != b[i]) { return false; } }
        return true;
    }

    private static byte[] concat(byte[] a, byte[] b)
    {
        byte[] out = new byte[a.length + b.length];
        System.arraycopy(a, 0, out, 0, a.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }

    // ==================================================================
    // One Minimum Security Level
    // ==================================================================

    /**
     * The three axis values plus any trailing MSL data.
     *
     * MSL data is the optional remainder of the Minimum Security Level field
     * after its first byte (TS 102 226 clause 8.2.1.3.2). It is card- and
     * profile-specific, so this class carries it verbatim and never invents one.
     */
    public static final class Level
    {
        public final int integrity;
        public final int cipher;
        public final int counter;
        public final byte[] data;

        public Level(int integrity, int cipher, int counter)
        {
            this(integrity, cipher, counter, new byte[0]);
        }

        public Level(int integrity, int cipher, int counter, byte[] data)
        {
            check("integrity", integrity, 3);
            check("cipher", cipher, 1);
            check("counter", counter, 3);
            this.integrity = integrity;
            this.cipher = cipher;
            this.counter = counter;
            this.data = (data == null) ? new byte[0] : (byte[]) data.clone();
        }

        private static void check(String name, int value, int maximum)
        {
            if (value < 0 || value > maximum)
            {
                throw new IllegalArgumentException(name + " out of range: " + value);
            }
        }

        public int toByte()
        {
            return spiFirstOctet(integrity, cipher, counter);
        }

        /** The whole Minimum Security Level field: parameter byte then MSL data. */
        public byte[] toField()
        {
            return concat(new byte[] { (byte) toByte() }, data);
        }

        public static Level fromByte(int value)
        {
            return fromByte(value, new byte[0]);
        }

        public static Level fromByte(int value, byte[] data)
        {
            if (value < 0 || value > 0xFF)
            {
                throw new IllegalArgumentException("MSL byte out of range: " + value);
            }
            if ((value & 0xE0) != 0)
            {
                // Not necessarily an error - a card may use the reserved bits
                // for something proprietary - but the caller must see it rather
                // than have it silently dropped on the next re-encode.
                throw new IllegalArgumentException("MSL byte " + hexByte(value)
                    + " sets the reserved bits b6-b8; carry it as raw MSL data instead of "
                    + "decoding it into a level");
            }
            return new Level(value & 0x03, (value >> 2) & 0x01, (value >> 3) & 0x03, data);
        }

        /** Null for a zero-length field, which means "no minimum enforced". */
        public static Level fromField(byte[] field)
        {
            if (field == null || field.length == 0) { return null; }

            byte[] extra = new byte[field.length - 1];
            System.arraycopy(field, 1, extra, 0, extra.length);
            return fromByte(field[0] & 0xFF, extra);
        }

        public int axis(int axis)
        {
            if (axis == AXIS_INTEGRITY) { return integrity; }
            if (axis == AXIS_CIPHER)    { return cipher; }
            return counter;
        }

        public Level withAxis(int axis, int value)
        {
            return new Level(axis == AXIS_INTEGRITY ? value : integrity,
                             axis == AXIS_CIPHER ? value : cipher,
                             axis == AXIS_COUNTER ? value : counter,
                             data);
        }

        /**
         * True when this level provides at least the other on every axis.
         *
         * Used only to PREDICT what a card should do. The discovery routine
         * measures each axis separately and never assumes this, because
         * TS 102 226 does not spell the comparison out byte for byte and
         * implementations have been seen to differ.
         */
        public boolean dominates(Level other)
        {
            return integrity >= other.integrity
                && cipher >= other.cipher
                && counter >= other.counter;
        }

        public String describe()
        {
            return hexByte(toByte()) + " (" + INTEGRITY_NAMES[integrity] + ", "
                + CIPHER_NAMES[cipher] + ", " + COUNTER_NAMES[counter] + ")"
                + (data.length == 0 ? "" : " + MSL data " + hex(data));
        }

        public boolean equals(Object other)
        {
            if (!(other instanceof Level)) { return false; }

            Level that = (Level) other;
            return toByte() == that.toByte() && equal(data, that.data);
        }

        public int hashCode()
        {
            return toByte() * 31 + data.length;
        }

        public String toString() { return describe(); }
    }

    // ==================================================================
    // TS 102 226 install parameters
    // ==================================================================
    //
    // The install parameters field of INSTALL [for install and make
    // selectable] carries, in TLV form:
    //
    //   C9 <len> <application specific parameters>   GlobalPlatform, the applet's own
    //   EF <len> <system specific parameters>        GlobalPlatform (C7 / C8)
    //   EA <len> CA <len> <toolkit parameters>       ETSI TS 102 226
    //
    // and the toolkit parameters (tag CA) are a fixed-order sequence of plain
    // fields, not TLVs:
    //
    //   priority                              1
    //   maximum number of timers              1
    //   maximum text length of a menu entry   1
    //   maximum number of menu entries  n =   1
    //   position + identifier per entry      2n
    //   maximum number of channels            1
    //   length of the Minimum Security Level  1
    //   Minimum Security Level              var   <-- the MSL byte, then MSL data
    //   length of the TAR field               1
    //   TAR value(s)                        3*m
    //
    // READ THIS BEFORE THE FIRST INSTALL ON A CARD YOU CARE ABOUT. That field
    // order is this tool's reading of TS 102 226 clause 8.2.1.3.2, and there is
    // no copy of the spec text on this machine to check it against. One hard
    // data point supports the MSL byte itself - the operator's vendor
    // spreadsheet documents MSL 0x12 as "Counter Higher, CC, No Ciphering",
    // which is exactly what Level.fromByte(0x12) decodes - but that confirms the
    // byte, not the field order around it. describeInstallParameters() prints
    // every byte with the field this code assigned it to, so the whole block can
    // be read against the spec in one pass, and the run dialog's "raw install
    // parameters" box bypasses this builder entirely when a profile disagrees.

    public static final int TAG_APPLICATION_SPECIFIC = 0xC9;
    public static final int TAG_SYSTEM_SPECIFIC = 0xEF;        // GlobalPlatform System Specific
    public static final int TAG_UICC_SYSTEM_SPECIFIC = 0xEA;   // ETSI UICC System Specific
    public static final int TAG_SIM_TOOLKIT = 0xCA;            // CA: SIM-format toolkit, lives in EF
    public static final int TAG_UICC_TOOLKIT = 0x80;           // 80: UICC-format toolkit, lives in EA

    /**
     * Which of the two install-parameter formats ETSI TS 102 226 defines.
     *
     * Confirmed from clause 8.2.1.3.2 of the spec itself (V9.4.0), not guessed:
     *   UICC: tag 'EA' (UICC System Specific) wrapping tag '80' (UICC Toolkit).
     *   SIM : tag 'EF' (System Specific)      wrapping tag 'CA' (SIM Toolkit).
     * And the spec is explicit that if both 'CA' and 'EA' appear the card
     * returns 6A80 - so the earlier EA-wrapping-CA this tool emitted was a
     * malformed cross of the two, and a strict card would have rejected it.
     * The inner byte order is identical for both, so one encoder serves both.
     */
    public static final int FORMAT_UICC = 0;
    public static final int FORMAT_SIM = 1;

    public static int toolkitTagFor(int format) { return format == FORMAT_SIM ? TAG_SIM_TOOLKIT : TAG_UICC_TOOLKIT; }
    public static int systemTagFor(int format)  { return format == FORMAT_SIM ? TAG_SYSTEM_SPECIFIC : TAG_UICC_SYSTEM_SPECIFIC; }

    /** One (position, identifier) pair; both 00 mean "the card decides". */
    public static final class MenuEntry
    {
        public final int position;
        public final int identifier;

        public MenuEntry(int position, int identifier)
        {
            this.position = position;
            this.identifier = identifier;
        }
    }

    /**
     * The tag 'CA' content.
     *
     * The defaults are deliberately empty - no timers, no menu entries, no
     * channels - because that is the right shape for an applet installed only
     * to have its MSL exercised, and anything else is a provisioning decision
     * that belongs to the operator rather than to a default.
     */
    public static final class Toolkit
    {
        public Level msl;                       // null means "emit no MSL field at all"
        public final List tars = new ArrayList();       // byte[3] each
        public final List menuEntries = new ArrayList();
        public int priority = 0x01;
        public int maxTimers = 0x00;
        public int maxMenuTextLength = 0x00;
        public int maxChannels = 0x00;

        public Toolkit(Level msl)
        {
            this.msl = msl;
        }

        public Toolkit addTar(byte[] tar)
        {
            if (tar == null || tar.length != 3)
            {
                throw new IllegalArgumentException("a TAR is 3 bytes, got "
                    + (tar == null ? "null" : hex(tar)));
            }
            tars.add(tar.clone());
            return this;
        }

        public byte[] encode()
        {
            List out = new ArrayList();
            add(out, priority);
            add(out, maxTimers);
            add(out, maxMenuTextLength);
            add(out, menuEntries.size());
            for (int i = 0; i < menuEntries.size(); i++)
            {
                MenuEntry entry = (MenuEntry) menuEntries.get(i);
                add(out, entry.position);
                add(out, entry.identifier);
            }
            add(out, maxChannels);

            byte[] mslField = (msl == null) ? new byte[0] : msl.toField();
            add(out, mslField.length);
            addAll(out, mslField);

            add(out, tars.size() * 3);
            for (int i = 0; i < tars.size(); i++)
            {
                addAll(out, (byte[]) tars.get(i));
            }
            return toArray(out);
        }

        private static void add(List out, int value)      { out.add(Integer.valueOf(value & 0xFF)); }
        private static void addAll(List out, byte[] data)
        {
            for (int i = 0; i < data.length; i++) { add(out, data[i] & 0xFF); }
        }
        private static byte[] toArray(List values)
        {
            byte[] out = new byte[values.size()];
            for (int i = 0; i < out.length; i++)
            {
                out[i] = (byte) ((Integer) values.get(i)).intValue();
            }
            return out;
        }
    }

    /** What parseToolkit() found, including a field-by-field trail for the dump. */
    public static final class ParsedToolkit
    {
        public int priority;
        public int maxTimers;
        public int maxMenuTextLength;
        public int maxChannels;
        public final List menuEntries = new ArrayList();
        public Level msl;
        public byte[] mslField = new byte[0];
        public final List tars = new ArrayList();
        public byte[] trailing = new byte[0];
        public final List fields = new ArrayList();     // String[] { offset, hex, description }
    }

    /**
     * Decodes a tag 'CA' value.
     *
     * Throws on truncation rather than returning a half-parsed object: a
     * silently truncated parse is exactly how a wrong MSL gets reported as a
     * right one.
     */
    public static ParsedToolkit parseToolkit(byte[] data)
    {
        ParsedToolkit parsed = new ParsedToolkit();
        int[] pos = { 0 };

        parsed.priority = take(data, pos, 1, "priority level", parsed)[0] & 0xFF;
        parsed.maxTimers = take(data, pos, 1, "maximum number of timers", parsed)[0] & 0xFF;
        parsed.maxMenuTextLength =
            take(data, pos, 1, "maximum menu entry text length", parsed)[0] & 0xFF;

        int entryCount = take(data, pos, 1, "maximum number of menu entries", parsed)[0] & 0xFF;
        for (int i = 0; i < entryCount; i++)
        {
            byte[] pair = take(data, pos, 2, "menu entry " + (i + 1)
                               + " (position, identifier)", parsed);
            parsed.menuEntries.add(new MenuEntry(pair[0] & 0xFF, pair[1] & 0xFF));
        }
        parsed.maxChannels = take(data, pos, 1, "maximum number of channels", parsed)[0] & 0xFF;

        int mslLength =
            take(data, pos, 1, "length of the Minimum Security Level field", parsed)[0] & 0xFF;
        if (mslLength > 0)
        {
            parsed.mslField = take(data, pos, mslLength, "Minimum Security Level", parsed);
            parsed.msl = Level.fromField(parsed.mslField);
        }

        int tarLength = take(data, pos, 1, "length of the TAR field", parsed)[0] & 0xFF;
        if (tarLength > 0)
        {
            if ((tarLength % 3) != 0)
            {
                throw new IllegalArgumentException("TAR field is " + tarLength
                    + " bytes, not a multiple of 3");
            }
            byte[] tars = take(data, pos, tarLength, "TAR value(s)", parsed);
            for (int i = 0; i < tarLength; i += 3)
            {
                byte[] tar = new byte[3];
                System.arraycopy(tars, i, tar, 0, 3);
                parsed.tars.add(tar);
            }
        }

        if (pos[0] < data.length)
        {
            parsed.trailing = new byte[data.length - pos[0]];
            System.arraycopy(data, pos[0], parsed.trailing, 0, parsed.trailing.length);
            parsed.fields.add(new String[] { String.valueOf(pos[0]), hex(parsed.trailing),
                                             "trailing bytes this parser did not consume" });
        }
        return parsed;
    }

    private static byte[] take(byte[] data, int[] pos, int count, String description,
                               ParsedToolkit parsed)
    {
        if (pos[0] + count > data.length)
        {
            throw new IllegalArgumentException("toolkit parameters truncated: " + description
                + " needs " + count + " byte(s) at offset " + pos[0] + ", only "
                + (data.length - pos[0]) + " left");
        }
        byte[] chunk = new byte[count];
        System.arraycopy(data, pos[0], chunk, 0, count);
        parsed.fields.add(new String[] { String.valueOf(pos[0]), hex(chunk), description });
        pos[0] += count;
        return chunk;
    }

    private static byte[] tlv(int tag, byte[] value)
    {
        if (value.length > 0xFF)
        {
            throw new IllegalArgumentException("this builder emits short-form lengths only; tag "
                + hexByte(tag) + " would need " + value.length + " bytes");
        }
        return concat(new byte[] { (byte) tag, (byte) value.length }, value);
    }

    /**
     * The complete install parameters field.
     *
     * C9 goes first and is emitted even when empty: GlobalPlatform requires the
     * application specific parameters tag to be present, and a card that
     * enforces that answers 6A80 to an otherwise perfect EA block.
     */
    public static byte[] buildInstallParameters(Toolkit toolkit, byte[] applicationSpecific,
                                                byte[] systemSpecific)
    {
        return buildInstallParameters(toolkit, applicationSpecific, systemSpecific, FORMAT_UICC);
    }

    public static byte[] buildInstallParameters(Toolkit toolkit, byte[] applicationSpecific,
                                                byte[] systemSpecific, int format)
    {
        byte[] out = tlv(TAG_APPLICATION_SPECIFIC,
                         applicationSpecific == null ? new byte[0] : applicationSpecific);
        if (systemSpecific != null && systemSpecific.length > 0)
        {
            out = concat(out, tlv(TAG_SYSTEM_SPECIFIC, systemSpecific));
        }
        if (toolkit != null)
        {
            // EA{80} for UICC, EF{CA} for SIM - never EA{CA}, which is 6A80.
            out = concat(out, tlv(systemTagFor(format),
                                  tlv(toolkitTagFor(format), toolkit.encode())));
        }
        return out;
    }

    /**
     * The tag 'CA' value inside an install parameters field, wherever it sits.
     *
     * Walks EA's children rather than assuming an offset, so it also reads back
     * parameters built by some other tool. Null means there is no toolkit block
     * at all, which is itself an answer to "what MSL does this applet have":
     * none was set at install time.
     */
    public static byte[] findToolkitParameters(byte[] installParameters)
    {
        List top = walkTlv(installParameters);
        for (int i = 0; i < top.size(); i++)
        {
            Object[] entry = (Object[]) top.get(i);
            int tag = ((Integer) entry[0]).intValue();
            byte[] value = (byte[]) entry[1];

            if (tag == TAG_UICC_TOOLKIT || tag == TAG_SIM_TOOLKIT) { return value; }

            if (tag == TAG_UICC_SYSTEM_SPECIFIC || tag == TAG_SYSTEM_SPECIFIC)
            {
                List inner = walkTlv(value);
                for (int j = 0; j < inner.size(); j++)
                {
                    Object[] child = (Object[]) inner.get(j);
                    int childTag = ((Integer) child[0]).intValue();
                    if (childTag == TAG_UICC_TOOLKIT || childTag == TAG_SIM_TOOLKIT)
                    {
                        return (byte[]) child[1];
                    }
                }
            }
        }
        return null;
    }

    /** The MSL an install parameters field declares, or null when it declares none. */
    public static Level mslOfInstallParameters(byte[] installParameters)
    {
        byte[] toolkit = findToolkitParameters(installParameters);
        if (toolkit == null) { return null; }

        return parseToolkit(toolkit).msl;
    }

    /**
     * How many trailing bytes a short-form TLV walk could not consume. Zero
     * means the field is well formed all the way to its end.
     *
     * walkTlv() below is deliberately tolerant - it stops at the first bad
     * length and returns what it read, which is the right behaviour for
     * anything a card hands back. That tolerance is wrong in one place: a raw
     * install parameters field pasted by an operator and about to be SENT. A
     * truncated block there parses to "no MSL found", which is
     * indistinguishable from a block that legitimately sets none, so it would
     * go to the card unremarked. This is the check that tells those apart.
     */
    public static int tlvRemainder(byte[] data)
    {
        if (data == null) { return 0; }

        int pos = 0;
        while (pos + 1 < data.length)
        {
            int length = data[pos + 1] & 0xFF;
            if (pos + 2 + length > data.length) { break; }
            pos += 2 + length;
        }
        return data.length - pos;
    }

    // ==================================================================
    // SMS-PP DOWNLOAD envelope, and the response packet that comes back
    //
    // These exist so one script can do both jobs. Card content management runs
    // on SCP02Script, and the SDK's ready-made OTA procedure runs on the other
    // script tree - so a merged script has to frame its own envelope. The
    // cryptography is still the SDK's (SecuredCommandPacketFactory builds the
    // packet, SecuredResponsePacketFactory reads the answer); what is here is
    // only the wrapping, which is plain bytes and therefore testable without a
    // card. Ported from the Python tool's build_envelope/parse_por, which is
    // the version already proven against this operator's cards.
    // ==================================================================

    /**
     * Wraps a secured command packet as an SMS-PP DOWNLOAD envelope,
     * ETSI TS 102 223 clause 7.1.1:
     *
     *   D1 len  82 02 83 81                device identities, network -> UICC
     *           8B len &lt;SMS-DELIVER TPDU&gt;
     *
     * The high bit on 82 and 8B is the comprehension-required flag CAT TLVs
     * carry (TS 101 220). Send the bare 02 and 0B instead and the envelope is
     * accepted and then quietly ignored: the card answers 6200 whatever the
     * key, TAR or counter, which reads exactly like a crypto failure and is not
     * one.
     *
     * The TPDU carries TP-UDHI, PID 7F (SIM data download) and DCS F6 (class 2,
     * 8-bit), and its user data is the UDH 02 70 00 - information element 70,
     * command packet identifier - followed by the packet itself.
     */
    public static byte[] buildEnvelope(byte[] commandPacket, String originatingAddress)
    {
        if (commandPacket == null) { throw new IllegalArgumentException("no command packet"); }

        String digits = (originatingAddress == null || originatingAddress.length() == 0)
            ? "0000000000" : originatingAddress;
        String padded = (digits.length() % 2 == 0) ? digits : digits + "F";

        byte[] address = new byte[padded.length() / 2];
        for (int i = 0; i < address.length; i++)
        {
            // Semi-octets: the two digits of each byte are swapped.
            address[i] = (byte) Integer.parseInt(
                "" + padded.charAt(i * 2 + 1) + padded.charAt(i * 2), 16);
        }

        byte[] userData = concat(new byte[] { 0x02, 0x70, 0x00 }, commandPacket);
        if (userData.length > 0xFF)
        {
            throw new IllegalArgumentException("the packet needs " + userData.length
                + " bytes of SMS user data; this builder does not split across concatenated SMS");
        }

        byte[] tpdu = new byte[] { 0x40 };                       // SMS-DELIVER, TP-UDHI set
        tpdu = concat(tpdu, new byte[] { (byte) digits.length(), (byte) 0x91 });
        tpdu = concat(tpdu, address);                            // TP-OA, international
        tpdu = concat(tpdu, new byte[] { 0x7F });                // TP-PID: SIM data download
        tpdu = concat(tpdu, new byte[] { (byte) 0xF6 });         // TP-DCS: class 2, 8-bit
        tpdu = concat(tpdu, new byte[7]);                        // TP-SCTS, not checked
        tpdu = concat(tpdu, new byte[] { (byte) userData.length });
        tpdu = concat(tpdu, userData);

        if (tpdu.length > 0xFF)
        {
            throw new IllegalArgumentException("the TPDU is " + tpdu.length + " bytes");
        }

        byte[] body = concat(new byte[] { (byte) 0x82, 0x02, (byte) 0x83, (byte) 0x81 },
                             new byte[] { (byte) 0x8B, (byte) tpdu.length });
        body = concat(body, tpdu);

        if (body.length > 0xFF)
        {
            throw new IllegalArgumentException("the envelope body is " + body.length + " bytes");
        }
        return concat(new byte[] { (byte) 0xD1, (byte) body.length }, body);
    }

    /** What a response packet says, once the wrapping is off. */
    public static final class Por
    {
        public final byte[] tar;
        public final byte[] counter;
        public final int status;
        public final byte[] responseData;

        Por(byte[] tar, byte[] counter, int status, byte[] responseData)
        {
            this.tar = tar;
            this.counter = counter;
            this.status = status;
            this.responseData = responseData;
        }
    }

    /**
     * Reads a TS 102 225 response packet out of the SMS user data:
     *
     *   02 71 00                   UDH: information element 71, response packet
     *   RPL(2) RHL(1) TAR(3) CNTR(5) PCNTR(1) STATUS(1) CC(RHL-10) &lt;data&gt;
     *
     * Walking the structure matters. Scanning for a recognisable status byte
     * finds the first byte of a compact response script instead - which begins
     * with the number of commands executed, and a 01 there looks exactly like
     * status 01, a MAC failure.
     *
     * The shortest legal packet is 13 bytes: no integrity field and no response
     * data, which is precisely what an 0A rejection looks like on a card that
     * sends no checksum on errors. Returns null when there is not even that.
     */
    public static Por parsePor(byte[] data)
    {
        if (data == null || data.length < 13) { return null; }

        int start = (data[0] == 0x02 && (data[1] & 0xFF) == 0x71) ? 3 : 0;
        if (data.length < start + 13) { return null; }

        int rhl = data[start + 2] & 0xFF;
        int body = start + 3;

        byte[] tar = slice(data, body, 3);
        byte[] counter = slice(data, body + 3, 5);
        int status = data[body + 9] & 0xFF;

        int checksumLength = Math.max(0, rhl - 10);
        int dataStart = body + 10 + checksumLength;
        byte[] responseData = (dataStart >= data.length)
            ? new byte[0] : slice(data, dataStart, data.length - dataStart);

        return new Por(tar, counter, status, responseData);
    }

    private static byte[] slice(byte[] data, int from, int length)
    {
        int real = Math.max(0, Math.min(length, data.length - from));
        byte[] out = new byte[real];
        System.arraycopy(data, from, out, 0, real);
        return out;
    }

    /** Short-form BER-TLV walk. Stops at the first length that overruns the buffer. */
    private static List walkTlv(byte[] data)
    {
        List out = new ArrayList();
        int pos = 0;
        while (data != null && pos + 1 < data.length)
        {
            int tag = data[pos] & 0xFF;
            int length = data[pos + 1] & 0xFF;
            if (pos + 2 + length > data.length) { break; }

            byte[] value = new byte[length];
            System.arraycopy(data, pos + 2, value, 0, length);
            out.add(new Object[] { Integer.valueOf(tag), value });
            pos += 2 + length;
        }
        return out;
    }

    /**
     * An annotated, byte-by-byte dump of an install parameters field.
     *
     * This is the artefact to read against TS 102 226 before the first install:
     * every byte is printed with the field this code believes it to be.
     */
    public static List describeInstallParameters(byte[] installParameters)
    {
        List lines = new ArrayList();
        List top = walkTlv(installParameters);

        for (int i = 0; i < top.size(); i++)
        {
            Object[] entry = (Object[]) top.get(i);
            int tag = ((Integer) entry[0]).intValue();
            byte[] value = (byte[]) entry[1];

            if (tag == TAG_APPLICATION_SPECIFIC)
            {
                lines.add("C9 " + hexByte(value.length) + "  application specific parameters"
                          + (value.length == 0 ? " (empty)" : " " + hex(value)));
            }
            else if (tag == TAG_SYSTEM_SPECIFIC)
            {
                lines.add("EF " + hexByte(value.length) + "  system specific parameters "
                          + hex(value));
            }
            else if (tag == TAG_UICC_SYSTEM_SPECIFIC)
            {
                lines.add("EA " + hexByte(value.length) + "  UICC system specific parameters");
                List inner = walkTlv(value);
                for (int j = 0; j < inner.size(); j++)
                {
                    Object[] child = (Object[]) inner.get(j);
                    int childTag = ((Integer) child[0]).intValue();
                    byte[] childValue = (byte[]) child[1];

                    if (childTag == TAG_UICC_TOOLKIT)
                    {
                        lines.add("  CA " + hexByte(childValue.length)
                                  + "  UICC toolkit application specific parameters");
                        describeToolkit(childValue, lines);
                    }
                    else
                    {
                        lines.add("  " + hexByte(childTag) + " " + hexByte(childValue.length)
                                  + "  " + hex(childValue));
                    }
                }
            }
            else
            {
                lines.add(hexByte(tag) + " " + hexByte(value.length) + "  " + hex(value));
            }
        }
        return lines;
    }

    private static void describeToolkit(byte[] value, List lines)
    {
        ParsedToolkit parsed;
        try
        {
            parsed = parseToolkit(value);
        }
        catch (RuntimeException e)
        {
            lines.add("    !! " + e.getMessage());
            lines.add("    raw: " + hex(value));
            return;
        }

        for (int i = 0; i < parsed.fields.size(); i++)
        {
            String[] field = (String[]) parsed.fields.get(i);
            lines.add("    +" + pad(field[0], 3) + " " + pad(field[1], 14) + " " + field[2]);
        }
        if (parsed.msl != null)
        {
            lines.add("    -> MSL " + parsed.msl.describe());
        }
        else
        {
            lines.add("    -> no Minimum Security Level field: this applet enforces no minimum");
        }
        for (int i = 0; i < parsed.tars.size(); i++)
        {
            lines.add("    -> TAR " + hex((byte[]) parsed.tars.get(i)));
        }
    }

    private static String pad(String text, int width)
    {
        StringBuilder out = new StringBuilder(text);
        while (out.length() < width) { out.append(' '); }
        return out.toString();
    }

    // ==================================================================
    // INSTALL [for install and make selectable]
    // ==================================================================

    /**
     * The raw APDU, for the paths that build it themselves (the normal-mode
     * tool, or RAM delivery inside a secured packet).
     *
     * MslScript's install job does NOT use this by default: the SDK's
     * InstallForInstallAndMakeSelectableCommand builds the same command from
     * typed fields, and going through the SDK keeps the secure channel wrapping
     * in one place. This exists so the two can be compared byte for byte when
     * an install is refused and the question is whose bytes are wrong.
     *
     * makeSelectable=false emits P1=04. That leaves the applet INSTALLED but not
     * SELECTABLE, and an applet that is not selectable is not reachable by its
     * TAR either - OTA answers 09 (TAR unknown) rather than anything about
     * security.
     */
    public static byte[] buildInstallApdu(byte[] loadFileAid, byte[] moduleAid,
                                          byte[] instanceAid, byte[] privileges,
                                          byte[] installParameters, boolean makeSelectable)
    {
        byte[] data = lengthPrefixed(loadFileAid);
        data = concat(data, lengthPrefixed(moduleAid));
        data = concat(data, lengthPrefixed(instanceAid));
        data = concat(data, lengthPrefixed(privileges));
        data = concat(data, lengthPrefixed(installParameters));
        data = concat(data, lengthPrefixed(new byte[0]));        // empty install token

        if (data.length > 0xFF)
        {
            throw new IllegalArgumentException("INSTALL data is " + data.length
                + " bytes; this builder emits a short Lc only");
        }
        byte[] header = { (byte) 0x80, (byte) 0xE6,
                          (byte) (makeSelectable ? 0x0C : 0x04), 0x00, (byte) data.length };
        return concat(header, data);
    }

    private static byte[] lengthPrefixed(byte[] value)
    {
        if (value == null) { value = new byte[0]; }
        if (value.length > 0xFF)
        {
            throw new IllegalArgumentException("field too long for a single-byte length: "
                + value.length + " bytes");
        }
        return concat(new byte[] { (byte) value.length }, value);
    }
}
