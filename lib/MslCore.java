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

    // ==================================================================
    // GET STATUS and DELETE
    //
    // Browsing and deleting are GlobalPlatform card content management, exactly
    // like INSTALL, and they travel the same two roads: inside an SCP02 secure
    // channel over the contact interface, or inside a secured packet addressed
    // to the card manager's TAR over OTA (Remote Application Management).
    //
    // The SDK has typed commands for the first road and MslScript uses them
    // there. Over OTA there is no secure channel to put a typed command object
    // in - the APDU has to exist as bytes before it can become the payload of a
    // packet - so the two commands are built here, card-free and under test.
    //
    // Governing specs: GlobalPlatform Card Specification 2.2 clause 11.3
    // (DELETE), clause 11.4 (GET STATUS) and ETSI TS 102 226 clause 5 for the
    // RAM response the card sends back.
    // ==================================================================

    /** GET STATUS P1: which part of the registry to list. */
    public static final int STATUS_ISSUER_SECURITY_DOMAIN = 0x80;
    public static final int STATUS_APPLICATIONS = 0x40;          // applications and SSDs
    public static final int STATUS_LOAD_FILES = 0x20;            // executable load files
    public static final int STATUS_LOAD_FILES_AND_MODULES = 0x10;

    public static String statusScopeLabel(int p1)
    {
        if (p1 == STATUS_ISSUER_SECURITY_DOMAIN)   { return "issuer security domain"; }
        if (p1 == STATUS_APPLICATIONS)             { return "applications and security domains"; }
        if (p1 == STATUS_LOAD_FILES)               { return "executable load files"; }
        if (p1 == STATUS_LOAD_FILES_AND_MODULES)   { return "load files and their modules"; }
        return "GET STATUS P1 " + hexByte(p1);
    }

    /** True when this scope's registry entries carry a module list after the privileges. */
    public static boolean scopeCarriesModules(int p1)
    {
        return p1 == STATUS_LOAD_FILES_AND_MODULES;
    }

    /**
     * GET STATUS.
     *
     * P2 bit b1 is "next occurrence" - the continuation after a 6310 - and bit
     * b2 selects the response format: clear for the deprecated (compact) format
     * every card supports, set for the GlobalPlatform 2.2 TLV format. The
     * deprecated format is the default here for the same reason MslScript asks
     * the SDK for it on the contact path: it is the one a 2.1.1 card answers at
     * all.
     *
     * An empty AID filter means "list everything", which is what tag 4F with
     * length 00 says. Le is present and 00: GET STATUS is a case 4 command, and
     * over RAM the card puts its answer in the response packet rather than
     * leaving it to a GET RESPONSE.
     */
    public static byte[] buildGetStatusApdu(int p1, byte[] aidFilter, boolean nextOccurrence,
                                            boolean tlvFormat)
    {
        // No Le: this tool's GET STATUS goes inside a secured packet far more
        // often than through a secure channel, and the RAM case is the one
        // where the byte does damage. The contact path asks for it explicitly.
        return buildGetStatusApdu(p1, aidFilter, nextOccurrence, tlvFormat, false);
    }

    /**
     * The same command, with the two things cards disagree about made explicit.
     *
     * `withLe` controls the trailing 00. GET STATUS is a case 4 command and the
     * byte belongs there over a contact channel, but inside a secured packet the
     * answer comes back in the response packet rather than through a GET
     * RESPONSE, and some card managers parse the command script strictly enough
     * that the extra byte is an error. `tlvFormat` picks the GlobalPlatform 2.2
     * TLV response over the deprecated one, which a 2.2-only card may require.
     *
     * Neither can be decided from a specification: the MCI/Hamrah card answered
     * 6F00 - no precise diagnosis - to the form that every other card here
     * accepts. So MslScript sends the forms in turn until one is accepted and
     * then stays with it, and says in the log which one the card wanted.
     */
    public static byte[] buildGetStatusApdu(int p1, byte[] aidFilter, boolean nextOccurrence,
                                            boolean tlvFormat, boolean withLe)
    {
        byte[] filter = (aidFilter == null) ? new byte[0] : aidFilter;
        if (filter.length > 0x10)
        {
            throw new IllegalArgumentException("an AID is 5 to 16 bytes; this filter is "
                + filter.length);
        }

        byte[] data = tlv(0x4F, filter);
        int p2 = (nextOccurrence ? 0x01 : 0x00) | (tlvFormat ? 0x02 : 0x00);

        byte[] header = { (byte) 0x80, (byte) 0xF2, (byte) p1, (byte) p2, (byte) data.length };
        byte[] apdu = concat(header, data);
        return withLe ? concat(apdu, new byte[] { 0x00 }) : apdu;
    }

    // ------------------------------------------------------------------
    // The GET STATUS forms, in the order they are worth trying
    // ------------------------------------------------------------------

    /**
     * bit 0 set = send Le; bit 1 set = ask for the TLV response format.
     *
     * No-Le first, because that is what a RAM command script wants and because
     * the MCI/Hamrah card proved why: sent WITH the Le byte it answered "2
     * commands executed, last one 6F00" to a script carrying one command. It
     * had read the trailing 00 as the start of a second, malformed command -
     * and since the compact response format reports only the last command's
     * status and data, the GET STATUS answer was thrown away.
     */
    public static final int[] STATUS_FORMS = { 0, 1, 2, 3 };

    public static boolean statusFormHasLe(int form)  { return (form & 1) != 0; }
    public static boolean statusFormIsTlv(int form)  { return (form & 2) != 0; }

    public static String statusFormLabel(int form)
    {
        return (statusFormIsTlv(form) ? "TLV response format (P2 bit b2)"
                                      : "deprecated response format")
            + (statusFormHasLe(form) ? ", with Le" : ", without Le");
    }

    /**
     * DELETE [card content].
     *
     * P2 00 deletes the object named and nothing else; P2 80 deletes it and
     * every related object - which for an executable load file means the load
     * file AND every applet instance made from it. That cascade is the only way
     * to remove a package whose instances are still present (the card answers
     * 6A80/6985 otherwise), and it is also the fastest way to delete more than
     * was intended, so it is never the default and MslScript names every AID it
     * is about to remove before it sends anything.
     *
     * There is no undo. A deleted applet instance takes its install parameters
     * with it, and that includes the MSL this whole tool exists to measure.
     */
    public static byte[] buildDeleteApdu(byte[] aid, boolean withRelatedObjects)
    {
        return buildDeleteApdu(aid, withRelatedObjects, false);
    }

    /**
     * The same command, with the trailing Le made explicit.
     *
     * Over a contact channel DELETE is a case 4 command and the byte belongs
     * there. Inside a secured packet it must NOT be sent: a RAM command script
     * is a sequence of case 3 APDUs, and a card that finds a byte after the
     * data reads it as the start of another command. That is not a guess -
     * the MCI/Hamrah card did exactly that to GET STATUS and reported two
     * commands executed where one was sent.
     */
    public static byte[] buildDeleteApdu(byte[] aid, boolean withRelatedObjects, boolean withLe)
    {
        if (aid == null || aid.length < 5 || aid.length > 16)
        {
            throw new IllegalArgumentException("an AID is 5 to 16 bytes, got "
                + (aid == null ? "null" : String.valueOf(aid.length)));
        }

        byte[] data = tlv(0x4F, aid);
        byte[] header = { (byte) 0x80, (byte) 0xE4, 0x00,
                          (byte) (withRelatedObjects ? 0x80 : 0x00), (byte) data.length };
        byte[] apdu = concat(header, data);
        return withLe ? concat(apdu, new byte[] { 0x00 }) : apdu;
    }

    /** A status word as four hex digits, for log lines and notes. */
    public static String hexWord(int status)
    {
        return hexByte(status >> 8) + hexByte(status);
    }

    /**
     * GET RESPONSE, for the command script that needs one.
     *
     * Inside a secured packet the card manager runs the script under T=0
     * rules: a command that produced data answers 61 xx - "xx bytes are
     * waiting" - and the data is only handed over to a GET RESPONSE. There is
     * no transport layer underneath to do that automatically the way there is
     * on a contact channel, so the script has to carry it as the next command.
     *
     * Confirmed live on the MCI/Hamrah card: GET STATUS without Le answered
     * 6159 (89 bytes of registry waiting) where the same command with an Le
     * byte answered 6F00. The 61 xx was never a refusal - it was the card
     * asking to be read.
     */
    public static byte[] buildGetResponseApdu(int length)
    {
        if (length < 0 || length > 0xFF)
        {
            throw new IllegalArgumentException("GET RESPONSE takes 0 to 255 bytes, not " + length);
        }
        return new byte[] { 0x00, (byte) 0xC0, 0x00, 0x00, (byte) length };
    }

    /**
     * Two APDUs as one command script.
     *
     * A RAM command script is simply case 3 APDUs end to end; the card walks it
     * and reports how many it executed plus the last one's status and data.
     * That last-one rule is what makes the pairing work: the GET RESPONSE is
     * last, so its data is what comes back.
     */
    public static byte[] commandScript(byte[] first, byte[] second)
    {
        return concat(first, second);
    }

    /** True when a status word is a card asking to be read: 61 xx or 6C xx. */
    public static boolean hasPendingData(int status)
    {
        return (status & 0xFF00) == 0x6100 || (status & 0xFF00) == 0x6C00;
    }

    // ------------------------------------------------------------------
    // What a RAM response packet carries
    // ------------------------------------------------------------------

    /**
     * The additional response data of a RAM packet, ETSI TS 102 226 clause 5.2,
     * compact format:
     *
     *   number of executed C-APDUs (1) | SW1 SW2 of the last one (2) | its response data
     *
     * Reading the status word matters more than it looks: a PoR status of 00
     * says the PACKET was accepted - MAC good, counter good, TAR resolved - and
     * says nothing at all about whether the command inside it worked. An INSTALL
     * that the card refused with 6A80 arrives inside a perfectly good PoR 00.
     * Every RAM step in MslScript checks this status word for 9000 as well.
     */
    public static final class RamResponse
    {
        public final int commands;
        public final int statusWord;
        public final byte[] data;

        RamResponse(int commands, int statusWord, byte[] data)
        {
            this.commands = commands;
            this.statusWord = statusWord;
            this.data = data;
        }

        public boolean ok() { return statusWord == 0x9000; }

        public String describe()
        {
            return commands + " command(s) executed, last answered " + hexWord(statusWord)
                + (data.length == 0 ? ", no response data"
                                    : ", " + data.length + " byte(s) of response data");
        }
    }

    /**
     * Reads the compact RAM response out of a PoR's response data. Null when
     * there is not even a status word there, which is what a PoR with no
     * additional data looks like - legal, and the normal answer to a command
     * that returns nothing.
     */
    public static RamResponse parseRamResponse(byte[] responseData)
    {
        if (responseData == null || responseData.length < 3) { return null; }

        int commands = responseData[0] & 0xFF;
        int status = ((responseData[1] & 0xFF) << 8) | (responseData[2] & 0xFF);
        byte[] data = (responseData.length == 3)
            ? new byte[0] : slice(responseData, 3, responseData.length - 3);
        return new RamResponse(commands, status, data);
    }

    // ------------------------------------------------------------------
    // The registry
    // ------------------------------------------------------------------

    /** One registry entry, from either GET STATUS response format. */
    public static final class Registry
    {
        public byte[] aid = new byte[0];
        public int lifeCycle = -1;
        public byte[] privileges = new byte[0];
        public final List modules = new ArrayList();      // byte[] each, load-file scopes only

        public String describe(int scope)
        {
            StringBuilder text = new StringBuilder();
            text.append(hex(aid));
            if (lifeCycle >= 0)
            {
                text.append("  life cycle ").append(hexByte(lifeCycle))
                    .append(" (").append(lifeCycleName(scope, lifeCycle)).append(")");
            }
            if (privileges.length > 0)
            {
                text.append("  privileges ").append(hex(privileges));
            }
            return text.toString();
        }
    }

    /**
     * The life cycle names GlobalPlatform 2.2 gives each scope (Tables 11-4 and
     * 11-5). The same byte means different things for a load file, an
     * application and the card manager, so the scope decides - and anything
     * unrecognised is reported as application-specific rather than guessed at,
     * because the upper bits are the applet's own to use.
     */
    public static String lifeCycleName(int scope, int value)
    {
        if (scope == STATUS_LOAD_FILES || scope == STATUS_LOAD_FILES_AND_MODULES)
        {
            return value == 0x01 ? "LOADED" : "application-specific";
        }
        if (scope == STATUS_ISSUER_SECURITY_DOMAIN)
        {
            if (value == 0x01) { return "OP_READY"; }
            if (value == 0x07) { return "INITIALIZED"; }
            if (value == 0x0F) { return "SECURED"; }
            if (value == 0x7F) { return "CARD_LOCKED"; }
            if (value == 0xFF) { return "TERMINATED"; }
            return "application-specific";
        }
        if ((value & 0x80) != 0) { return "LOCKED"; }
        if (value == 0x03) { return "INSTALLED"; }
        if (value == 0x07) { return "SELECTABLE"; }
        if (value == 0x0F) { return "PERSONALIZED (security domain)"; }
        return "application-specific";
    }

    /**
     * The deprecated (compact) GET STATUS response format:
     *
     *   AID length(1) AID  life cycle(1)  privileges(1)
     *   [ number of modules(1)  then per module: AID length(1) AID ]
     *
     * The module list exists only for P1=10, which is why the scope has to be
     * passed in: the two shapes are indistinguishable from the bytes alone, and
     * a parser that guessed would read a module count as the next entry's AID
     * length and hand back a registry of plausible nonsense.
     *
     * Tolerant on purpose at the end - a card may truncate the list and say
     * 6310, meaning "ask again with P2 next-occurrence" - so a trailing
     * fragment stops the walk instead of throwing. What it will not do is
     * invent a field: an entry is added only once its AID is complete.
     */
    public static List parseRegistryCompact(byte[] data, int scope)
    {
        List out = new ArrayList();
        if (data == null) { return out; }

        int pos = 0;
        while (pos < data.length)
        {
            int length = data[pos] & 0xFF;
            if (length == 0 || pos + 1 + length > data.length) { break; }

            Registry entry = new Registry();
            entry.aid = slice(data, pos + 1, length);
            pos += 1 + length;

            if (pos < data.length) { entry.lifeCycle = data[pos] & 0xFF; pos++; }
            if (pos < data.length) { entry.privileges = slice(data, pos, 1); pos++; }

            if (scopeCarriesModules(scope) && pos < data.length)
            {
                int modules = data[pos] & 0xFF;
                pos++;
                for (int i = 0; i < modules && pos < data.length; i++)
                {
                    int moduleLength = data[pos] & 0xFF;
                    if (moduleLength == 0 || pos + 1 + moduleLength > data.length) { break; }
                    entry.modules.add(slice(data, pos + 1, moduleLength));
                    pos += 1 + moduleLength;
                }
            }
            out.add(entry);
        }
        return out;
    }

    /**
     * The GlobalPlatform 2.2 TLV format: one E3 template per entry, carrying
     * tag 4F (AID), 9F70 (life cycle), C5 (privileges) and 84 (module AID,
     * repeated).
     *
     * Only offered because some cards answer in it even when the deprecated
     * format was asked for, and reading one format as the other produces
     * entries rather than an error.
     */
    public static List parseRegistryTlv(byte[] data)
    {
        List out = new ArrayList();
        List templates = walkBer(data);

        for (int i = 0; i < templates.size(); i++)
        {
            Object[] template = (Object[]) templates.get(i);
            if (((Integer) template[0]).intValue() != 0xE3) { continue; }

            Registry entry = new Registry();
            List fields = walkBer((byte[]) template[1]);
            for (int j = 0; j < fields.size(); j++)
            {
                Object[] field = (Object[]) fields.get(j);
                int tag = ((Integer) field[0]).intValue();
                byte[] value = (byte[]) field[1];

                if (tag == 0x4F)                       { entry.aid = value; }
                else if (tag == 0x9F70 && value.length > 0) { entry.lifeCycle = value[0] & 0xFF; }
                else if (tag == 0xC5)                  { entry.privileges = value; }
                else if (tag == 0x84)                  { entry.modules.add(value); }
            }
            if (entry.aid.length > 0) { out.add(entry); }
        }
        return out;
    }

    /**
     * Whichever format the card actually used. A GET STATUS response that opens
     * with E3 is the TLV one; anything else is read as the deprecated format,
     * which is what was asked for.
     */
    public static List parseRegistry(byte[] data, int scope)
    {
        if (data != null && data.length > 0 && (data[0] & 0xFF) == 0xE3)
        {
            return parseRegistryTlv(data);
        }
        return parseRegistryCompact(data, scope);
    }

    /**
     * BER-TLV walk with two-byte tags and the 81/82 length forms, which the
     * registry format needs (tag 9F70) and the short-form walk above does not
     * handle. Stops at the first field that overruns, like its sibling.
     */
    private static List walkBer(byte[] data)
    {
        List out = new ArrayList();
        int pos = 0;

        while (data != null && pos + 1 < data.length)
        {
            int tag = data[pos] & 0xFF;
            pos++;
            if ((tag & 0x1F) == 0x1F)                  // the tag continues into a second byte
            {
                if (pos >= data.length) { break; }
                tag = (tag << 8) | (data[pos] & 0xFF);
                pos++;
            }
            if (pos >= data.length) { break; }

            int length = data[pos] & 0xFF;
            pos++;
            if (length == 0x81)
            {
                if (pos >= data.length) { break; }
                length = data[pos] & 0xFF;
                pos++;
            }
            else if (length == 0x82)
            {
                if (pos + 1 >= data.length) { break; }
                length = ((data[pos] & 0xFF) << 8) | (data[pos + 1] & 0xFF);
                pos += 2;
            }
            else if (length > 0x80)
            {
                break;                                 // a longer length form: not in a registry
            }

            if (pos + length > data.length) { break; }
            out.add(new Object[] { Integer.valueOf(tag), slice(data, pos, length) });
            pos += length;
        }
        return out;
    }
}
