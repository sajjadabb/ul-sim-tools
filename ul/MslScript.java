// GENERATED FILE - do not edit. Regenerate with:
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
// Bundled: MslCore.java, MslCapLoad.java, MslProbing.java, MslProfile.java, MslLog.java, MslReport.java, UlChoices.java, MslConfig.java, MslConfigDialog.java, MslScript.java


import aspects.applications.threeg.scp80.CipherMode;
import aspects.applications.threeg.scp80.CounterMode;
import aspects.applications.threeg.scp80.DefaultSCP80Security;
import aspects.applications.threeg.scp80.IntegrityLevel;
import aspects.applications.threeg.scp80.PoRMode;
import aspects.applications.threeg.scp80.PoRSMSType;
import aspects.applications.threeg.scp80.SCP80Security;
import aspects.applications.threeg.scp80.SCP80SecurityParameters;
import aspects.applications.threeg.scp80.SPI;
import aspects.applications.threeg.scp80.SecuredCommandPacket;
import aspects.applications.threeg.scp80.SecuredCommandPacketFactory;
import com.aspectssoftware.simulation.iso7816.GenericISOCommand;
import com.aspectssoftware.simulation.iso7816.ISOResponse;
import com.aspectssoftware.simulation.terminal.TerminalResourceKeys;
import nl.collis.api.simulation.gp.ApplicationLifeCycleState;
import nl.collis.api.simulation.gp.scp02.SecurityLevel;
import nl.collis.api.simulation.terminal.gp.commands.DeleteCommand;
import nl.collis.api.simulation.terminal.gp.commands.GetStatusCommand;
import nl.collis.api.simulation.terminal.gp.commands.GetStatusResponse;
import nl.collis.api.simulation.terminal.gp.commands.GetStatusSequence;
import nl.collis.api.simulation.terminal.gp.commands.InstallForInstallAndMakeSelectableCommand;
import nl.collis.api.simulation.terminal.gp.commands.InstallForInstallCommand;
import nl.collis.api.simulation.terminal.gp.commands.InstallForLoadCommand;
import nl.collis.api.simulation.terminal.gp.commands.LoadSequence;
import nl.collis.api.simulation.terminal.gp.commands.RegistryData;
import nl.collis.api.simulation.terminal.gp.commands.SelectCommand;
import nl.collis.api.simulation.terminal.gp.scp02.SCP02KeyVersion;
import nl.collis.api.simulation.terminal.gp.scp02.SCP02Script;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.Frame;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.io.Writer;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.concurrent.CountDownLatch;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JComponent;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.JScrollPane;
import javax.swing.JTabbedPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;
import javax.swing.UIManager;
import javax.swing.WindowConstants;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;

// --------------------------------------------------------------------------
// lib/MslCore.java
// --------------------------------------------------------------------------

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
final class MslCore
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

// --------------------------------------------------------------------------
// lib/MslCapLoad.java
// --------------------------------------------------------------------------

/**
 * CAP loading: a Java Card .cap file turned into INSTALL [for load], the LOAD
 * block chain and nothing else. No card, no reader, no SDK - the same rule
 * MslCore follows, for the same reason: this is the file the self-test and the
 * Python port (tools/capload.py) mirror, method for method.
 *
 * Why this exists next to the SDK's own LoadSequence, which MslScript already
 * uses for the contact/SCP02 path: over OTA each APDU has to be wrapped in its
 * own secured packet and has to fit a single SMS-PP envelope, so the LOAD chain
 * has to be chunked at a size this tool chooses (about 160 bytes, not the 255 a
 * contact channel allows). That means the blocks are built here.
 *
 * Building them here is only safe because it is checked rather than trusted, in
 * two independent ways:
 *
 *   1. MslScript.otaInstall() computes the load file with this class AND asks
 *      the SDK's LoadSequence for the same CAP's load file AID and load file
 *      data block hash, and refuses to send anything if either disagrees. A
 *      SHA-1 match over the whole load file means this class's concatenation is
 *      the SDK's own byte for byte - which is the thing that must be exactly
 *      right, and the thing a comment cannot establish.
 *   2. MslSelfTest reassembles the blocks back into the load file and checks
 *      every length field, against a synthetic CAP built in the test itself, so
 *      the gate runs with no CAP on the machine.
 *
 * Load File Data Block = the CAP components concatenated in the JavaCard
 * download order (JCVM 2.2 spec clause 6.2), Debug excluded. Each component
 * already carries its own tag + size header, so the block is a straight
 * concatenation in that order and nothing is re-serialized.
 *
 * Governing specs: GlobalPlatform Card Specification 2.2 clause 11.5.2.3
 * (INSTALL [for load]) and clause 11.6 (LOAD).
 */
final class MslCapLoad
{
    private MslCapLoad() { }

    /**
     * The download order. Debug is never part of a load file; Applet is absent
     * from a library CAP, and a component that is not in the archive is simply
     * skipped rather than faked.
     */
    public static final String[] LOAD_ORDER = {
        "Header.cap", "Directory.cap", "Import.cap", "Applet.cap", "Class.cap",
        "Method.cap", "StaticField.cap", "ConstantPool.cap", "RefLocation.cap",
        "Descriptor.cap",
    };

    /** The default LOAD block size: see fitsOneEnvelope() for where 160 comes from. */
    public static final int DEFAULT_BLOCK_SIZE = 160;

    /**
     * The largest LOAD APDU that still fits one SMS-PP envelope.
     *
     * A secured packet adds 25 bytes of header (CPL, CHL, SPI, KIc, KID, TAR,
     * CNTR, PCNTR, 8-byte CC), the UDH adds 3, the SMS-DELIVER TPDU about 18 and
     * the CAT envelope 8 - so an APDU above this cannot be delivered in a single
     * packet whatever the card thinks of it. tools/selftest_capload.py asserts
     * the same bound on the Python side.
     */
    public static final int MAX_OTA_APDU = 197;

    // ------------------------------------------------------------------
    // Reading the archive
    // ------------------------------------------------------------------

    /**
     * Every .cap component in the archive, keyed by its bare file name.
     *
     * A CAP puts its components under a package directory, and the directory
     * name is the package's, so the key has to be the base name. Where an
     * archive holds the same base name twice the last one wins, which is what
     * the Python twin's dictionary does.
     */
    public static Map readComponents(File capFile) throws IOException
    {
        Map components = new HashMap();
        ZipFile archive = new ZipFile(capFile);
        try
        {
            Enumeration entries = archive.entries();
            while (entries.hasMoreElements())
            {
                ZipEntry entry = (ZipEntry) entries.nextElement();
                if (entry.isDirectory()) { continue; }

                String name = entry.getName();
                int slash = Math.max(name.lastIndexOf('/'), name.lastIndexOf('\\'));
                String base = slash < 0 ? name : name.substring(slash + 1);
                if (!base.endsWith(".cap")) { continue; }

                components.put(base, readFully(archive.getInputStream(entry)));
            }
        }
        finally
        {
            archive.close();
        }
        return components;
    }

    private static byte[] readFully(InputStream stream) throws IOException
    {
        try
        {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            byte[] buffer = new byte[8192];
            int read = stream.read(buffer);
            while (read > 0)
            {
                out.write(buffer, 0, read);
                read = stream.read(buffer);
            }
            return out.toByteArray();
        }
        finally
        {
            stream.close();
        }
    }

    /**
     * The package AID out of the Header component, which is also the load file
     * (ELF) AID.
     *
     * Header layout, JCVM 2.2 clause 6.3: tag(1) size(2) magic(4) minor(1)
     * major(1) flags(1) then the package - minor(1) major(1) AID length(1) AID.
     */
    public static byte[] packageAid(Map components)
    {
        byte[] header = (byte[]) components.get("Header.cap");
        if (header == null)
        {
            throw new IllegalArgumentException("this CAP has no Header.cap component, so it "
                + "declares no package AID");
        }

        int offset = 3 + 4 + 2 + 1 + 2;
        if (offset >= header.length)
        {
            throw new IllegalArgumentException("Header.cap is truncated: "
                + header.length + " bytes");
        }

        int length = header[offset] & 0xFF;
        if (offset + 1 + length > header.length)
        {
            throw new IllegalArgumentException("Header.cap declares a " + length
                + "-byte package AID but holds only " + (header.length - offset - 1)
                + " byte(s) after the length");
        }
        byte[] aid = new byte[length];
        System.arraycopy(header, offset + 1, aid, 0, length);
        return aid;
    }

    /**
     * Every applet AID the Applet component declares, in order. Empty for a
     * library CAP, which has no Applet component at all.
     *
     * Applet layout: tag(1) size(2) count(1) then per applet - AID length(1)
     * AID install_method_offset(2).
     */
    public static List appletAids(Map components)
    {
        List out = new ArrayList();
        byte[] applet = (byte[]) components.get("Applet.cap");
        if (applet == null) { return out; }

        int pos = 3;
        if (pos >= applet.length) { return out; }

        int count = applet[pos] & 0xFF;
        pos++;
        for (int i = 0; i < count; i++)
        {
            if (pos >= applet.length)
            {
                throw new IllegalArgumentException("Applet.cap declares " + count
                    + " applet(s) but runs out after " + i);
            }
            int length = applet[pos] & 0xFF;
            pos++;
            if (pos + length > applet.length)
            {
                throw new IllegalArgumentException("Applet.cap declares a " + length
                    + "-byte AID that overruns the component");
            }
            byte[] aid = new byte[length];
            System.arraycopy(applet, pos, aid, 0, length);
            out.add(aid);
            pos += length + 2;              // + install_method_offset
        }
        return out;
    }

    /** The components concatenated in download order, Debug excluded. */
    public static byte[] loadFileDataBlock(Map components)
    {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (int i = 0; i < LOAD_ORDER.length; i++)
        {
            byte[] component = (byte[]) components.get(LOAD_ORDER[i]);
            if (component != null)
            {
                out.write(component, 0, component.length);
            }
        }
        return out.toByteArray();
    }

    /** SHA-1 of the load file data block, which is what INSTALL [for load] carries. */
    public static byte[] loadFileHash(byte[] loadFile)
    {
        try
        {
            return MessageDigest.getInstance("SHA-1").digest(loadFile);
        }
        catch (NoSuchAlgorithmException e)
        {
            // Every JRE has SHA-1; this cannot happen, and if it somehow does
            // the run must stop rather than send an INSTALL with no hash.
            throw new IllegalStateException("SHA-1 is not available in this JRE", e);
        }
    }

    // ------------------------------------------------------------------
    // The APDUs
    // ------------------------------------------------------------------

    /** BER-TLV length encoding, for the C4 tag the LOAD chain carries. */
    public static byte[] berLength(int value)
    {
        if (value < 0) { throw new IllegalArgumentException("negative length: " + value); }
        if (value < 0x80) { return new byte[] { (byte) value }; }

        int bytes = (value <= 0xFF) ? 1 : ((value <= 0xFFFF) ? 2 : ((value <= 0xFFFFFF) ? 3 : 4));
        byte[] out = new byte[1 + bytes];
        out[0] = (byte) (0x80 | bytes);
        for (int i = bytes; i >= 1; i--)
        {
            out[i] = (byte) (value & 0xFF);
            value >>= 8;
        }
        return out;
    }

    /**
     * INSTALL [for load], GlobalPlatform 2.2 clause 11.5.2.3:
     *
     *   data = [ELF AID LV][SD AID LV][load file hash LV][load parameters LV][token LV]
     *
     * The hash is optional per GlobalPlatform and included anyway: a card that
     * requires it answers 6A80 without one, and computing it costs nothing.
     */
    public static byte[] buildInstallForLoad(byte[] elfAid, byte[] loadFile, byte[] sdAid,
                                             boolean withHash, byte[] loadParameters)
    {
        byte[] data = lv(elfAid);
        data = concat(data, lv(sdAid));
        data = concat(data, lv(withHash ? loadFileHash(loadFile) : new byte[0]));
        data = concat(data, lv(loadParameters));
        data = concat(data, lv(new byte[0]));          // empty load token

        if (data.length > 0xFF)
        {
            throw new IllegalArgumentException("INSTALL [for load] data is " + data.length
                + " bytes; this builder emits a short Lc only");
        }
        return concat(new byte[] { (byte) 0x80, (byte) 0xE6, 0x02, 0x00, (byte) data.length },
                      data);
    }

    /**
     * The LOAD chain, GlobalPlatform 2.2 clause 11.6.
     *
     * The load file data block is prefixed with tag C4 and its BER length, and
     * that whole thing - tag and length included - is what gets split. P1 bit 8
     * marks the last block, P2 is the block sequence number counting from 00.
     *
     * The sequence number is what a card uses to notice a block that arrived
     * twice or out of order, which over OTA is not hypothetical: an SMS can be
     * delivered late. It starts at 00 here, as the Python twin and its tests do.
     */
    public static List buildLoadBlocks(byte[] loadFile, int blockSize)
    {
        if (blockSize < 1 || blockSize > 0xFF)
        {
            throw new IllegalArgumentException("a LOAD block is 1 to 255 bytes of data, not "
                + blockSize);
        }

        byte[] tagged = concat(concat(new byte[] { (byte) 0xC4 }, berLength(loadFile.length)),
                               loadFile);
        List blocks = new ArrayList();
        int offset = 0;
        int sequence = 0;

        while (offset < tagged.length)
        {
            int length = Math.min(blockSize, tagged.length - offset);
            byte[] chunk = new byte[length];
            System.arraycopy(tagged, offset, chunk, 0, length);
            offset += length;

            boolean last = offset >= tagged.length;
            byte[] header = { (byte) 0x80, (byte) 0xE8, (byte) (last ? 0x80 : 0x00),
                              (byte) (sequence & 0xFF), (byte) length };
            blocks.add(concat(header, chunk));
            sequence++;
        }

        if (sequence > 0x100)
        {
            throw new IllegalArgumentException("the load file needs " + sequence
                + " LOAD blocks; the sequence number is one byte, so raise the block size");
        }
        return blocks;
    }

    /** True when this APDU still fits a single SMS-PP envelope once wrapped. */
    public static boolean fitsOneEnvelope(byte[] apdu)
    {
        return apdu != null && apdu.length <= MAX_OTA_APDU;
    }

    // ------------------------------------------------------------------
    // The whole sequence
    // ------------------------------------------------------------------

    /** What a CAP turns into: the AIDs it declares, its load file, and the APDUs. */
    public static final class Sequence
    {
        public final byte[] elfAid;
        public final List appletAids;            // byte[] each, in declaration order
        public final byte[] loadFile;
        public final byte[] loadFileHash;
        public final List apdus;                 // byte[] each: INSTALL [for load], then LOAD
        public final List names;                 // String each, one per APDU, for the log

        Sequence(byte[] elfAid, List appletAids, byte[] loadFile, List apdus, List names)
        {
            this.elfAid = elfAid;
            this.appletAids = appletAids;
            this.loadFile = loadFile;
            this.loadFileHash = loadFileHash(loadFile);
            this.apdus = apdus;
            this.names = names;
        }

        /** The APDU that does not fit one envelope, or null when they all do. */
        public byte[] firstOversizedApdu()
        {
            for (int i = 0; i < apdus.size(); i++)
            {
                byte[] apdu = (byte[]) apdus.get(i);
                if (!fitsOneEnvelope(apdu)) { return apdu; }
            }
            return null;
        }
    }

    public static Sequence read(File capFile, int blockSize) throws IOException
    {
        Map components = readComponents(capFile);
        byte[] elfAid = packageAid(components);
        byte[] loadFile = loadFileDataBlock(components);
        if (loadFile.length == 0)
        {
            throw new IllegalArgumentException("the load file data block is empty: this archive "
                + "holds no CAP component this loader recognises");
        }

        List apdus = new ArrayList();
        List names = new ArrayList();
        apdus.add(buildInstallForLoad(elfAid, loadFile, new byte[0], true, new byte[0]));
        names.add("INSTALL [for load]");

        List blocks = buildLoadBlocks(loadFile, blockSize);
        for (int i = 0; i < blocks.size(); i++)
        {
            apdus.add(blocks.get(i));
            names.add("LOAD block " + i + " of " + blocks.size());
        }
        return new Sequence(elfAid, appletAids(components), loadFile, apdus, names);
    }

    // ------------------------------------------------------------------

    private static byte[] lv(byte[] value)
    {
        if (value == null) { value = new byte[0]; }
        if (value.length > 0xFF)
        {
            throw new IllegalArgumentException("INSTALL [for load] field too long: "
                + value.length + " bytes");
        }
        return concat(new byte[] { (byte) value.length }, value);
    }

    private static byte[] concat(byte[] a, byte[] b)
    {
        byte[] out = new byte[a.length + b.length];
        System.arraycopy(a, 0, out, 0, a.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }
}

// --------------------------------------------------------------------------
// lib/MslProbing.java
// --------------------------------------------------------------------------

/**
 * What the card can be asked about its MSL, and what its answers mean.
 *
 * Nothing here sends anything. Every routine takes a Sender - anything that can
 * turn a Probe into a Result - so the same inference runs against the real card
 * through MslScript, against a plain PC/SC reader through the Python port,
 * and against SimulatedCard in the self-test. Keeping the algorithm separate
 * from the transport is what makes it testable without a card at all.
 *
 * Java port of the second half of tools/mslcore.py.
 */
final class MslProbing
{
    private MslProbing() { }

    /** The card did not reject the packet on security-level grounds. */
    public static final String ACCEPTED = "ACCEPTED";
    /** Response status 0A - insufficient security level. */
    public static final String BELOW_MSL = "BELOW_MSL";
    /** No PoR, or an answer that says nothing about the MSL. */
    public static final String INCONCLUSIVE = "INCONCLUSIVE";

    // ------------------------------------------------------------------

    /** One point in the (integrity, ciphering, counter) lattice. */
    public static final class Probe
    {
        public final int integrity;
        public final int cipher;
        public final int counter;

        public Probe(int integrity, int cipher, int counter)
        {
            this.integrity = integrity;
            this.cipher = cipher;
            this.counter = counter;
        }

        public Probe withAxis(int axis, int value)
        {
            return new Probe(axis == MslCore.AXIS_INTEGRITY ? value : integrity,
                             axis == MslCore.AXIS_CIPHER ? value : cipher,
                             axis == MslCore.AXIS_COUNTER ? value : counter);
        }

        public int spiFirstOctet()
        {
            return MslCore.spiFirstOctet(integrity, cipher, counter);
        }

        public MslCore.Level asLevel()
        {
            return new MslCore.Level(integrity, cipher, counter);
        }

        public String key()
        {
            return integrity + "/" + cipher + "/" + counter;
        }

        public String describe()
        {
            return "SPI1=" + MslCore.hexByte(spiFirstOctet()) + " ("
                + MslCore.axisValueName(MslCore.AXIS_INTEGRITY, integrity) + ", "
                + MslCore.axisValueName(MslCore.AXIS_CIPHER, cipher) + ", "
                + MslCore.axisValueName(MslCore.AXIS_COUNTER, counter) + ")";
        }
    }

    public static final class Result
    {
        public final Probe probe;
        public final String outcome;
        public final int status;          // the PoR response status byte, or -1 for none
        public final String note;

        public Result(Probe probe, String outcome, int status, String note)
        {
            this.probe = probe;
            this.outcome = outcome;
            this.status = status;
            this.note = (note == null) ? "" : note;
        }

        public String describe()
        {
            return probe.describe() + " -> " + outcome
                + (status < 0 ? "  no PoR" : "  status " + MslCore.hexByte(status))
                + (note.length() == 0 ? "" : "  " + note);
        }
    }

    public interface Sender
    {
        Result send(Probe probe);
    }

    /**
     * Turns a PoR into one of the three outcomes.
     *
     * The one thing that matters here: the MSL check happens BEFORE the
     * integrity and counter checks, so 01 (RC/CC/DS failed) and 02/03 (counter
     * low/high) all mean the packet got PAST the security-level gate. Treating
     * them as failures would make the tool report "the card rejects everything"
     * whenever the key was slightly wrong - the single easiest way to get a
     * confident wrong answer out of this kind of probing.
     *
     * Returns { outcome, note }.
     */
    public static String[] classify(int status, boolean porReceived)
    {
        if (!porReceived || status < 0)
        {
            return new String[] { INCONCLUSIVE,
                "no PoR came back - with no answer there is nothing to conclude about the "
                + "security level" };
        }
        if (status == 0x0A)
        {
            return new String[] { BELOW_MSL, "insufficient security level" };
        }
        if (status == 0x00)
        {
            return new String[] { ACCEPTED, "" };
        }
        if (status >= 0x01 && status <= 0x06)
        {
            return new String[] { ACCEPTED,
                "the packet passed the security-level gate and then failed a later check (status "
                + MslCore.hexByte(status) + ") - that is still evidence the MSL was met" };
        }
        if (status == 0x09)
        {
            return new String[] { INCONCLUSIVE,
                "TAR unknown - this TAR does not resolve to an installed, selectable "
                + "application, so no MSL is being applied at all" };
        }
        return new String[] { ACCEPTED,
            "status " + MslCore.hexByte(status) + " - past the security-level gate" };
    }

    /**
     * The strongest packet the tooling in front of this card can actually build.
     *
     * This is our limit, not the card's: no KIc key means no ciphering, and
     * "counter exactly one higher" can only be sent once the card's own counter
     * is known. Discovery holds the two axes it is not measuring at these
     * values, so an axis we cannot reach is never mistaken for a card that
     * rejects everything.
     */
    public static final class Ceiling
    {
        public final int integrity;
        public final int cipher;
        public final int counter;

        public Ceiling(int integrity, int cipher, int counter)
        {
            this.integrity = integrity;
            this.cipher = cipher;
            this.counter = counter;
        }

        public int axis(int axis)
        {
            if (axis == MslCore.AXIS_INTEGRITY) { return integrity; }
            if (axis == MslCore.AXIS_CIPHER)    { return cipher; }
            return counter;
        }

        public Probe probe()
        {
            return new Probe(integrity, cipher, counter);
        }

        public Probe probeWith(int axis, int value)
        {
            return probe().withAxis(axis, value);
        }

        public String describe()
        {
            return "integrity <= " + MslCore.axisValueName(MslCore.AXIS_INTEGRITY, integrity)
                + ", cipher <= " + MslCore.axisValueName(MslCore.AXIS_CIPHER, cipher)
                + ", counter <= " + MslCore.axisValueName(MslCore.AXIS_COUNTER, counter);
        }
    }

    /** Thrown when a run would exceed the probe budget. Not an error - a stop. */
    public static final class BudgetExhausted extends RuntimeException
    {
        private static final long serialVersionUID = 1L;

        public BudgetExhausted(String message) { super(message); }
    }

    /** Memoises probes so an axis walk never pays twice for the same point. */
    public static final class Oracle
    {
        private final Sender sender;
        private final int budget;
        private final boolean silentDrop;
        private boolean baselineSeen;
        private final Map cache = new HashMap();
        public final List results = new ArrayList();

        public Oracle(Sender sender, int budget)
        {
            this(sender, budget, false);
        }

        /**
         * silentDrop handles cards that do NOT answer 0A for a below-MSL packet
         * but discard it with no PoR (an anti-oracle hardening: without the key
         * the card refuses to leak its security map). A drop is then ambiguous -
         * below-MSL, counter-too-low and a comms error look alike - so it only
         * becomes meaningful after a baseline probe has returned a PoR, which
         * proves the key, counter, TAR and link are all good. From then on a
         * no-PoR result can only be the axis just weakened, i.e. below MSL.
         * Before any baseline PoR a drop stays INCONCLUSIVE, so a card that
         * answers nothing at all is never misread as "rejects everything".
         */
        public Oracle(Sender sender, int budget, boolean silentDrop)
        {
            this.sender = sender;
            this.budget = budget;
            this.silentDrop = silentDrop;
        }

        public Result probe(Probe probe)
        {
            Result cached = (Result) cache.get(probe.key());
            if (cached != null) { return cached; }

            if (results.size() >= budget)
            {
                throw new BudgetExhausted("probe budget of " + budget + " reached");
            }
            Result result = sender.send(probe);

            if (ACCEPTED.equals(result.outcome))
            {
                baselineSeen = true;
            }
            else if (silentDrop && baselineSeen
                     && INCONCLUSIVE.equals(result.outcome) && result.status < 0)
            {
                result = new Result(result.probe, BELOW_MSL, result.status,
                    "no PoR after a confirmed baseline -- read as below-MSL on a card that "
                    + "discards below-MSL packets silently (original: " + result.note + ")");
            }

            cache.put(probe.key(), result);
            results.add(result);
            return result;
        }
    }

    // ==================================================================
    // Task 3 - find the MSL of an installed applet
    // ==================================================================

    public static final class Discovery
    {
        public MslCore.Level msl;                    // null when it could not be pinned down
        public final int[] thresholds = { -1, -1, -1 };
        public final String[] undetermined = new String[3];
        public boolean confirmed;
        public final List notes = new ArrayList();
        public List results = new ArrayList();

        public List describe()
        {
            List lines = new ArrayList(notes);
            for (int i = 0; i < MslCore.AXES.length; i++)
            {
                int axis = MslCore.AXES[i];
                if (thresholds[axis] < 0)
                {
                    lines.add(MslCore.axisLabel(axis) + " : undetermined - "
                              + (undetermined[axis] == null ? "" : undetermined[axis]));
                }
                else
                {
                    lines.add(MslCore.axisLabel(axis) + " : "
                              + MslCore.axisValueName(axis, thresholds[axis]));
                }
            }
            if (msl == null)
            {
                lines.add("MSL: could not be determined from these probes");
            }
            else
            {
                lines.add("MSL: " + msl.describe()
                          + (confirmed ? "  (confirmed by check probes)"
                                       : "  (NOT confirmed - see the check probes above)"));
            }
            return lines;
        }
    }

    /**
     * Finds an applet's MSL by measuring each axis rather than assuming one.
     *
     * 1. Probe the ceiling. If that is rejected with 0A, the card wants more
     *    than this tooling can build and no axis can be isolated - stop and say
     *    so rather than reporting a floor of "everything is rejected".
     * 2. For each axis, hold the other two at the ceiling and walk that axis
     *    upwards from its weakest value. The first value not rejected with 0A
     *    is the card's minimum on that axis.
     * 3. Check the answer: the inferred level itself must be accepted, and one
     *    notch below it on each non-zero axis must come back 0A.
     *
     * Step 3 is what separates this from a plausible guess. An applet whose MSL
     * is enforced on only some axes, or a card that compares the MSL byte as a
     * whole rather than field by field, fails step 3 and is reported as
     * unconfirmed - with the probe log - instead of being rounded into a tidy
     * answer.
     */
    public static Discovery discover(Oracle oracle, Ceiling ceiling)
    {
        Discovery discovery = new Discovery();

        Probe top = ceiling.probe();
        Result topResult = oracle.probe(top);

        if (BELOW_MSL.equals(topResult.outcome))
        {
            discovery.notes.add(
                "The strongest packet this tooling can build (" + top.describe()
                + ") was rejected with 0A. The applet's MSL is above the reachable ceiling ("
                + ceiling.describe() + "), so the individual axes cannot be separated. Supply a "
                + "KIc key for ciphering, or a stronger integrity algorithm, and run again.");
            discovery.results = oracle.results;
            return discovery;
        }
        if (INCONCLUSIVE.equals(topResult.outcome))
        {
            discovery.notes.add(
                "The strongest packet this tooling can build got no usable answer ("
                + topResult.note + "). Nothing further was sent - fix that first: check that "
                + "TERMINAL PROFILE was accepted, that the counter is above the card's, and that "
                + "the TAR is an installed, selectable applet.");
            discovery.results = oracle.results;
            return discovery;
        }

        for (int i = 0; i < MslCore.AXES.length; i++)
        {
            int axis = MslCore.AXES[i];
            int limit = ceiling.axis(axis);
            int found = -1;

            for (int value = 0; value <= limit; value++)
            {
                String outcome = oracle.probe(ceiling.probeWith(axis, value)).outcome;

                if (ACCEPTED.equals(outcome))
                {
                    found = value;
                    break;
                }
                if (INCONCLUSIVE.equals(outcome))
                {
                    // Silence is not "rejected". Reading it that way pushes the
                    // threshold a notch too high and produces a confident wrong MSL.
                    discovery.undetermined[axis] = "a probe at "
                        + MslCore.axisValueName(axis, value)
                        + " got no usable answer, so the walk cannot be trusted past it";
                    break;
                }
            }

            if (found < 0 && discovery.undetermined[axis] == null)
            {
                discovery.undetermined[axis] = "every value up to the ceiling ("
                    + MslCore.axisValueName(axis, limit) + ") was rejected with 0A";
            }
            discovery.thresholds[axis] = found;
        }

        discovery.results = oracle.results;
        for (int i = 0; i < MslCore.AXES.length; i++)
        {
            if (discovery.thresholds[MslCore.AXES[i]] < 0) { return discovery; }
        }

        discovery.msl = new MslCore.Level(discovery.thresholds[MslCore.AXIS_INTEGRITY],
                                          discovery.thresholds[MslCore.AXIS_CIPHER],
                                          discovery.thresholds[MslCore.AXIS_COUNTER]);
        discovery.confirmed = confirm(oracle, discovery.msl, discovery.notes);
        discovery.results = oracle.results;
        return discovery;
    }

    /** The check probes: the level itself must pass, one notch below must not. */
    private static boolean confirm(Oracle oracle, MslCore.Level level, List notes)
    {
        boolean ok = true;

        Probe atLevel = new Probe(level.integrity, level.cipher, level.counter);
        if (!ACCEPTED.equals(oracle.probe(atLevel).outcome))
        {
            notes.add("check probe: a packet built at exactly the inferred MSL was not accepted");
            ok = false;
        }

        for (int i = 0; i < MslCore.AXES.length; i++)
        {
            int axis = MslCore.AXES[i];
            int value = level.axis(axis);
            if (value == 0) { continue; }

            String outcome = oracle.probe(atLevel.withAxis(axis, value - 1)).outcome;
            if (!BELOW_MSL.equals(outcome))
            {
                notes.add("check probe: lowering " + MslCore.axisLabel(axis)
                          + " one notch below the inferred MSL was answered " + outcome
                          + ", not 0A - the card is not enforcing that axis the way a field-wise "
                          + "MSL comparison would");
                ok = false;
            }
        }
        return ok;
    }

    // ==================================================================
    // Task 2 - check that an applet's MSL is the one it was installed with
    // ==================================================================

    public static final class Verification
    {
        public final MslCore.Level claimed;
        public boolean passed;
        public final List checks = new ArrayList();      // String[] { PASS/FAIL, what, expected, got }
        public final List notes = new ArrayList();
        public List results = new ArrayList();

        public Verification(MslCore.Level claimed) { this.claimed = claimed; }

        public List describe()
        {
            List lines = new ArrayList(notes);
            for (int i = 0; i < checks.size(); i++)
            {
                String[] check = (String[]) checks.get(i);
                lines.add("[" + check[0] + "] " + check[1] + "  expected " + check[2]
                          + ", got " + check[3]);
            }
            lines.add("VERDICT: the card " + (passed ? "does" : "does NOT demonstrably")
                      + " enforce MSL " + claimed.describe());
            return lines;
        }
    }

    /**
     * Behavioural proof that a specific MSL is in force.
     *
     * Two directions, because either alone is worthless:
     *
     *   not too high - a packet at exactly the claimed MSL must not be rejected
     *                  with 0A; if it is, the card wants more than was asked for.
     *   not too low  - for every axis the claimed MSL is above zero on, a packet
     *                  one notch weaker on that axis alone must be rejected with
     *                  0A. If it is accepted, the card enforces less than was
     *                  asked for - an applet reachable at a lower security level
     *                  than its profile claims, which is the finding that
     *                  actually matters.
     *
     * An axis the claimed MSL leaves at zero cannot be probed from below, and is
     * reported as untested rather than silently passed.
     */
    public static Verification verify(Oracle oracle, MslCore.Level claimed, Ceiling ceiling)
    {
        Verification verification = new Verification(claimed);

        Probe atLevel = new Probe(claimed.integrity, claimed.cipher, claimed.counter);
        String outcome = oracle.probe(atLevel).outcome;
        boolean ok = ACCEPTED.equals(outcome);
        verification.checks.add(new String[] { ok ? "PASS" : "FAIL",
            "a packet at exactly the claimed MSL is accepted", ACCEPTED, outcome });
        boolean allOk = ok;

        for (int i = 0; i < MslCore.AXES.length; i++)
        {
            int axis = MslCore.AXES[i];
            int value = claimed.axis(axis);

            if (value == 0)
            {
                verification.notes.add(MslCore.axisLabel(axis) + " is already at its weakest value "
                    + "in the claimed MSL, so there is nothing below it to probe - this axis is "
                    + "untested.");
                continue;
            }

            outcome = oracle.probe(atLevel.withAxis(axis, value - 1)).outcome;
            ok = BELOW_MSL.equals(outcome);
            allOk = allOk && ok;
            verification.checks.add(new String[] { ok ? "PASS" : "FAIL",
                "one notch below on " + MslCore.axisLabel(axis) + " is rejected with 0A",
                BELOW_MSL, outcome });
        }

        verification.passed = allOk;
        verification.results = oracle.results;
        return verification;
    }

    // ==================================================================
    // A card that exists only to test the inference
    // ==================================================================

    /**
     * An applet with a known MSL. Used by MslSelfTest to check that discovery
     * recovers every one of the 32 possible levels, and that the two behaviours
     * which break naive probing do not break this one: a card that answers a bad
     * MAC with 01 (which must still count as "security level accepted"), and one
     * that stays silent below its MSL instead of answering 0A.
     */
    public static final class SimulatedCard implements Sender
    {
        private final MslCore.Level msl;
        private final boolean wrongKey;
        private final boolean silentBelowMsl;
        public int sent;

        public SimulatedCard(MslCore.Level msl, boolean wrongKey, boolean silentBelowMsl)
        {
            this.msl = msl;
            this.wrongKey = wrongKey;
            this.silentBelowMsl = silentBelowMsl;
        }

        public Result send(Probe probe)
        {
            sent++;

            if (!probe.asLevel().dominates(msl))
            {
                if (silentBelowMsl)
                {
                    String[] classified = classify(-1, false);
                    return new Result(probe, classified[0], -1, classified[1]);
                }
                String[] classified = classify(0x0A, true);
                return new Result(probe, classified[0], 0x0A, classified[1]);
            }

            int status = wrongKey ? 0x01 : 0x00;
            String[] classified = classify(status, true);
            return new Result(probe, classified[0], status, classified[1]);
        }
    }
}

// --------------------------------------------------------------------------
// lib/MslProfile.java
// --------------------------------------------------------------------------

/**
 * Optional, non-secret pre-fill for the run dialog.
 *
 * Its whole purpose is that nobody retypes an ISD AID forty times. It is not a
 * configuration file in the usual sense: the dialog is still the only thing
 * that decides what gets sent, every value here is editable there, and the
 * run cannot start without the operator confirming the values against the card
 * actually in the reader.
 *
 * Key material is deliberately not loadable from here. Keys are typed fresh
 * every run because the operator swaps test SIMs between runs, and a key that
 * survives a card swap is a key that gets sent to the wrong card. If a
 * properties file does carry a key-looking entry, it is ignored and a line is
 * printed saying so, rather than silently honoured.
 */
final class MslProfile
{
    private static final String[] REFUSED_KEYS = {
        "scp02.enc", "scp02.mac", "scp02.dek", "ota.key", "key", "adm", "pin", "puk" };

    private final Properties values = new Properties();

    private MslProfile() { }

    /**
     * Reads config/msl.properties, looking beside the working directory and one
     * level up so it works whether a script is launched from the project root
     * or from the UL tool's own directory. A missing file is normal.
     */
    public static MslProfile load()
    {
        MslProfile profile = new MslProfile();
        String[] candidates = {
            "config/msl.properties",
            "msl-checking/config/msl.properties",
            "../config/msl.properties" };

        for (int i = 0; i < candidates.length; i++)
        {
            File file = new File(candidates[i]);
            if (!file.isFile()) { continue; }

            InputStream stream = null;
            try
            {
                stream = new FileInputStream(file);
                profile.values.load(stream);
                profile.stripSecrets(file.getPath());
                break;
            }
            catch (IOException e)
            {
                // A pre-fill that cannot be read is not worth failing a run over.
            }
            finally
            {
                if (stream != null) { try { stream.close(); } catch (IOException ignored) { } }
            }
        }
        return profile;
    }

    private void stripSecrets(String path)
    {
        stripSecrets(values, path);
    }

    /**
     * Removes every key-looking entry from a properties set, printing one line
     * per removal.
     *
     * Static and separate from load() so the self-test can exercise it without
     * a file on disk: this is a safety claim ("credentials are never loaded
     * from a file"), and a safety claim with no test is just a comment.
     */
    static void stripSecrets(Properties values, String path)
    {
        java.util.Iterator names = new java.util.ArrayList(values.keySet()).iterator();
        while (names.hasNext())
        {
            String name = String.valueOf(names.next());
            String lower = name.toLowerCase();

            for (int i = 0; i < REFUSED_KEYS.length; i++)
            {
                if (lower.indexOf(REFUSED_KEYS[i]) >= 0)
                {
                    values.remove(name);
                    System.out.println("MSL profile: ignoring '" + name + "' from " + path
                                       + " - credentials are typed into the dialog, never loaded "
                                       + "from a file.");
                    break;
                }
            }
        }
    }

    public String get(String name, String fallback)
    {
        String value = values.getProperty(name);
        return (value == null || value.trim().length() == 0) ? fallback : value.trim();
    }
}

// --------------------------------------------------------------------------
// lib/MslLog.java
// --------------------------------------------------------------------------

/**
 * A live log window, plus an echo into the platform's own script output.
 *
 * A probing run is a sequence of one-line answers and the interesting part is
 * watching them arrive - a walk that stops after two probes has already told
 * you something. The tool's own output panel is written to as well, so the
 * transcript survives after the window is closed.
 *
 * Everything is posted to the event dispatch thread, because a script runs on
 * its own thread and Swing is not thread-safe.
 */
final class MslLog
{
    private final PrintWriter output;
    private JFrame frame;
    private JTextArea area;

    public MslLog(String title, PrintWriter output)
    {
        this.output = output;
        build(title);
    }

    private void build(final String title)
    {
        Runnable create = new Runnable()
        {
            public void run()
            {
                area = new JTextArea(28, 110);
                area.setEditable(false);
                area.setFont(new Font("Monospaced", Font.PLAIN, 12));

                frame = new JFrame(title);
                frame.getContentPane().add(new JScrollPane(area), BorderLayout.CENTER);
                frame.setPreferredSize(new Dimension(980, 560));
                frame.pack();
                frame.setLocationByPlatform(true);
                frame.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
                frame.setVisible(true);
            }
        };

        if (SwingUtilities.isEventDispatchThread()) { create.run(); }
        else
        {
            try { SwingUtilities.invokeAndWait(create); }
            catch (Exception ignored) { /* head-less or CLI: the output panel still gets everything */ }
        }
    }

    public void heading(String text)
    {
        line("");
        line("=== " + text + " ===");
    }

    public void info(String text)  { line("     " + text); }
    public void step(String text)  { line("  -  " + text); }
    public void good(String text)  { line("  ok " + text); }
    public void warn(String text)  { line("  !  " + text); }
    public void error(String text) { line("  X  " + text); }

    public void lines(java.util.List texts)
    {
        for (int i = 0; i < texts.size(); i++) { info(String.valueOf(texts.get(i))); }
    }

    public void line(final String text)
    {
        if (output != null)
        {
            output.println(text);
            output.flush();
        }
        if (area == null) { return; }

        SwingUtilities.invokeLater(new Runnable()
        {
            public void run()
            {
                area.append(text + "\n");
                area.setCaretPosition(area.getDocument().getLength());
            }
        });
    }

    /** Leaves the window open so the run can be read after the script ends. */
    /**
     * The verdict, in a block that cannot be missed in a scrolling log.
     *
     * A run that ends in a wall of probe lines leaves the reader to work out
     * what happened. This says it once, plainly, in the words the report uses.
     */
    public void verdict(String verdict, String headline, String detail)
    {
        line("");
        line("========================================================================");
        line("  " + verdict + "   " + (headline == null ? "" : headline));
        if (detail != null && detail.length() > 0)
        {
            line("  " + detail);
        }
        line("========================================================================");
        line("");
    }

    public void markFinished()
    {
        line("");
        line("--- run finished; this window can be closed ---");
    }
}

// --------------------------------------------------------------------------
// lib/MslReport.java
// --------------------------------------------------------------------------

/**
 * The run, written down.
 *
 * A live log window is gone the moment the tool closes, and the UL certificate
 * is not something a colleague can open next week without the platform. This
 * builds two files instead: an HTML page to read, and a CSV row per probe to
 * grep or drop in a spreadsheet.
 *
 * Building and writing are separate on purpose. toHtml() and toCsv() are pure
 * string functions over what the run collected, so MslSelfTest can check the
 * verdict really does appear, that a key never does, and that a failed run is
 * never rendered as a pass - none of which needs a file system, let alone a
 * card.
 *
 * What a report must never do is flatter the run. A probe that got no answer is
 * INCONCLUSIVE here as everywhere else, an unconfirmed discovery says so in the
 * verdict line, and the caveat about what a PASS does and does not prove is
 * printed in the report rather than left in someone's memory.
 */
final class MslReport
{
    /** Verdicts, in the order of how much they claim. */
    public static final String PASS = "PASS";
    public static final String FAIL = "FAIL";
    public static final String UNCONFIRMED = "UNCONFIRMED";
    public static final String UNKNOWN = "UNKNOWN";

    private final MslConfig config;
    private final String job;
    private final String startedAt;

    private String verdict = UNKNOWN;
    private String headline = "";
    private String detail = "";

    private final List probes = new ArrayList();      // MslProbing.Result
    private final List notes = new ArrayList();       // String
    private final List installLines = new ArrayList();// String

    public MslReport(MslConfig config, String job)
    {
        this.config = config;
        this.job = job;
        this.startedAt = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date());
    }

    public void verdict(String verdict, String headline, String detail)
    {
        this.verdict = verdict;
        this.headline = headline == null ? "" : headline;
        this.detail = detail == null ? "" : detail;
    }

    public void probes(List results)
    {
        if (results != null) { probes.addAll(results); }
    }

    public void note(String text)
    {
        if (text != null && text.length() > 0) { notes.add(text); }
    }

    public void installLine(String text)
    {
        if (text != null) { installLines.add(text); }
    }

    public String getVerdict() { return verdict; }

    /** True only for a verdict that actually claims the thing was demonstrated. */
    public boolean passed() { return PASS.equals(verdict); }

    // ------------------------------------------------------------------
    // CSV - one row per probe, then one summary row
    // ------------------------------------------------------------------

    public String toCsv()
    {
        StringBuilder out = new StringBuilder();
        out.append("kind,card,job,tar,probe,spi1,security,outcome,por,note\n");

        for (int i = 0; i < probes.size(); i++)
        {
            MslProbing.Result result = (MslProbing.Result) probes.get(i);
            out.append("probe,")
               .append(csv(config.cardLabel)).append(",")
               .append(csv(job)).append(",")
               .append(csv(MslCore.hex(config.targetTar))).append(",")
               .append(i + 1).append(",")
               .append(MslCore.hexByte(result.probe.spiFirstOctet())).append(",")
               .append(csv(security(result.probe))).append(",")
               .append(csv(result.outcome)).append(",")
               .append(result.status < 0 ? "" : MslCore.hexByte(result.status)).append(",")
               .append(csv(result.note)).append("\n");
        }

        out.append("result,")
           .append(csv(config.cardLabel)).append(",")
           .append(csv(job)).append(",")
           .append(csv(MslCore.hex(config.targetTar))).append(",")
           .append(probes.size()).append(",,,")
           .append(csv(verdict)).append(",,")
           .append(csv(headline.length() == 0 ? detail : headline)).append("\n");

        return out.toString();
    }

    // ------------------------------------------------------------------
    // HTML - the one a person reads
    // ------------------------------------------------------------------

    public String toHtml()
    {
        StringBuilder out = new StringBuilder();
        out.append("<!DOCTYPE html>\n<html><head><meta charset=\"utf-8\">\n");
        out.append("<title>MSL run - ").append(html(config.cardLabel)).append("</title>\n");
        out.append("<style>\n").append(css()).append("</style>\n</head>\n<body>\n");

        out.append("<h1>Minimum Security Level &mdash; ").append(html(job)).append("</h1>\n");
        out.append("<p class=\"sub\">").append(html(config.cardLabel));
        if (config.operator != null && config.operator.trim().length() > 0)
        {
            out.append(" &middot; ").append(html(config.operator));
        }
        out.append(" &middot; ").append(html(startedAt)).append("</p>\n");

        out.append("<div class=\"verdict ").append(cssClass()).append("\">");
        out.append("<div class=\"tag\">").append(html(verdict)).append("</div>");
        out.append("<div><strong>").append(html(headline)).append("</strong>");
        if (detail.length() > 0)
        {
            out.append("<div class=\"detail\">").append(html(detail)).append("</div>");
        }
        out.append("</div></div>\n");

        out.append("<h2>Run</h2>\n<pre class=\"cfg\">")
           .append(html(config.describeForCertificate()))
           .append("</pre>\n");
        out.append("<p class=\"fine\">No key material appears in this report. Credentials are "
                   + "typed into the run dialog and are never written to a file.</p>\n");

        if (!installLines.isEmpty())
        {
            out.append("<h2>Install parameters</h2>\n<pre class=\"dump\">");
            for (int i = 0; i < installLines.size(); i++)
            {
                out.append(html(String.valueOf(installLines.get(i)))).append("\n");
            }
            out.append("</pre>\n");
        }

        if (!probes.isEmpty())
        {
            out.append("<h2>Probes</h2>\n<table>\n");
            out.append("<tr><th>#</th><th>SPI1</th><th>Security applied</th>"
                       + "<th>Outcome</th><th>PoR</th><th>What it means</th></tr>\n");

            for (int i = 0; i < probes.size(); i++)
            {
                MslProbing.Result result = (MslProbing.Result) probes.get(i);
                out.append("<tr class=\"").append(outcomeClass(result.outcome)).append("\">");
                out.append("<td>").append(i + 1).append("</td>");
                out.append("<td class=\"hex\">")
                   .append(MslCore.hexByte(result.probe.spiFirstOctet())).append("</td>");
                out.append("<td>").append(html(security(result.probe))).append("</td>");
                out.append("<td><span class=\"chip\">").append(html(result.outcome))
                   .append("</span></td>");
                out.append("<td class=\"hex\">")
                   .append(result.status < 0 ? "&mdash;" : MslCore.hexByte(result.status))
                   .append("</td>");
                out.append("<td>").append(html(result.note)).append("</td>");
                out.append("</tr>\n");
            }
            out.append("</table>\n");
        }

        if (!notes.isEmpty())
        {
            out.append("<h2>Notes</h2>\n<ul>\n");
            for (int i = 0; i < notes.size(); i++)
            {
                out.append("<li>").append(html(String.valueOf(notes.get(i)))).append("</li>\n");
            }
            out.append("</ul>\n");
        }

        out.append("<h2>What this does and does not prove</h2>\n<ul class=\"fine\">\n");
        out.append("<li>Response status <code>0A</code> is the only evidence of a Minimum "
                   + "Security Level. Nothing on a card reads install parameters back, so "
                   + "behaviour is the whole of the case.</li>\n");
        out.append("<li>A packet answered <code>01</code> (integrity) or <code>02</code>/"
                   + "<code>03</code> (counter) got <em>past</em> the security gate and counts "
                   + "as accepted here. A wrong key therefore cannot turn into a wrong MSL.</li>\n");
        out.append("<li>A probe with no PoR is INCONCLUSIVE, never a rejection. Reading silence "
                   + "as <code>0A</code> would push a threshold one notch too high.</li>\n");
        out.append("<li>The toolkit parameter field order is this tool's reading of ETSI "
                   + "TS 102 226 clause 8.2.1.3.2. Check the dump above against the spec before "
                   + "trusting an install on a card that matters.</li>\n");
        out.append("</ul>\n");

        out.append("<p class=\"fine\">MSL checking &mdash; UL Mobile Card Test Platform 3.8.0"
                   + "</p>\n</body></html>\n");
        return out.toString();
    }

    // ------------------------------------------------------------------
    // Writing
    // ------------------------------------------------------------------

    /**
     * Writes both files into the folder and returns the HTML one.
     *
     * The name carries the card label and the timestamp, so two runs on two
     * cards cannot overwrite each other - which is the whole reason a report
     * folder is worth having rather than one fixed file.
     */
    public File writeTo(String folder) throws IOException
    {
        File directory = new File(folder);
        if (!directory.isDirectory())
        {
            throw new IOException("not a folder: " + directory.getAbsolutePath());
        }

        String stamp = new SimpleDateFormat("yyyyMMdd-HHmmss").format(new Date());
        String base = "msl-" + job + "-" + safe(config.cardLabel) + "-" + stamp;

        File html = new File(directory, base + ".html");
        write(html, toHtml());
        write(new File(directory, base + ".csv"), toCsv());
        return html;
    }

    private static void write(File file, String text) throws IOException
    {
        Writer writer = new OutputStreamWriter(new FileOutputStream(file), "UTF-8");
        try
        {
            writer.write(text);
        }
        finally
        {
            writer.close();
        }
    }

    static String safe(String text)
    {
        if (text == null) { return "card"; }

        StringBuilder out = new StringBuilder();
        for (int i = 0; i < text.length(); i++)
        {
            char ch = text.charAt(i);
            boolean ok = (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z')
                || (ch >= '0' && ch <= '9') || ch == '-' || ch == '_';
            out.append(ok ? ch : '-');
        }
        String result = out.toString();
        return result.length() == 0 ? "card" : result;
    }

    // ------------------------------------------------------------------

    private static String security(MslProbing.Probe probe)
    {
        return MslCore.axisValueName(MslCore.AXIS_INTEGRITY, probe.integrity) + ", "
             + MslCore.axisValueName(MslCore.AXIS_CIPHER, probe.cipher) + ", "
             + MslCore.axisValueName(MslCore.AXIS_COUNTER, probe.counter);
    }

    private String cssClass()
    {
        if (PASS.equals(verdict))        { return "good"; }
        if (FAIL.equals(verdict))        { return "bad"; }
        return "warn";
    }

    private static String outcomeClass(String outcome)
    {
        if (MslProbing.ACCEPTED.equals(outcome))  { return "accepted"; }
        if (MslProbing.BELOW_MSL.equals(outcome)) { return "below"; }
        return "unclear";
    }

    private static String csv(String text)
    {
        if (text == null) { return ""; }

        String cleaned = text.replace('\n', ' ').replace('\r', ' ');
        if (cleaned.indexOf(',') < 0 && cleaned.indexOf('"') < 0) { return cleaned; }

        return "\"" + cleaned.replace("\"", "\"\"") + "\"";
    }

    static String html(String text)
    {
        if (text == null) { return ""; }

        StringBuilder out = new StringBuilder();
        for (int i = 0; i < text.length(); i++)
        {
            char ch = text.charAt(i);
            if (ch == '<')      { out.append("&lt;"); }
            else if (ch == '>') { out.append("&gt;"); }
            else if (ch == '&') { out.append("&amp;"); }
            else if (ch == '"') { out.append("&quot;"); }
            else                { out.append(ch); }
        }
        return out.toString();
    }

    private static String css()
    {
        return "body{font:14px/1.55 'Segoe UI',system-ui,sans-serif;color:#101828;"
             + "background:#f6f7f9;margin:0;padding:28px 32px;}"
             + "h1{font-size:20px;margin:0 0 2px;}"
             + "h2{font-size:14px;text-transform:uppercase;letter-spacing:.04em;color:#475467;"
             + "margin:26px 0 8px;}"
             + ".sub{color:#667085;margin:0 0 18px;}"
             + ".verdict{display:flex;gap:14px;align-items:center;padding:14px 16px;"
             + "border-radius:10px;border:1px solid #e4e7ec;background:#fff;}"
             + ".verdict .tag{font:700 13px/1 'Cascadia Mono',Consolas,monospace;padding:8px 12px;"
             + "border-radius:8px;color:#fff;}"
             + ".verdict .detail{color:#475467;font-size:13px;margin-top:3px;}"
             + ".verdict.good{background:#ecfdf3;border-color:#abefc6;}"
             + ".verdict.good .tag{background:#067647;}"
             + ".verdict.bad{background:#fef3f2;border-color:#fecdca;}"
             + ".verdict.bad .tag{background:#b42318;}"
             + ".verdict.warn{background:#fffaeb;border-color:#fedf89;}"
             + ".verdict.warn .tag{background:#b54708;}"
             + "table{border-collapse:collapse;width:100%;background:#fff;border:1px solid #e4e7ec;"
             + "border-radius:10px;overflow:hidden;font-size:13px;}"
             + "th{text-align:left;background:#f9fafb;color:#475467;font-size:11px;"
             + "text-transform:uppercase;letter-spacing:.04em;padding:9px 12px;"
             + "border-bottom:1px solid #e4e7ec;}"
             + "td{padding:9px 12px;border-bottom:1px solid #f2f4f7;vertical-align:top;}"
             + "tr:last-child td{border-bottom:0;}"
             + ".hex{font-family:'Cascadia Mono',Consolas,monospace;}"
             + ".chip{display:inline-block;padding:2px 8px;border-radius:999px;font-size:11px;"
             + "font-weight:600;}"
             + ".accepted .chip{background:#ecfdf3;color:#067647;}"
             + ".below .chip{background:#fef3f2;color:#b42318;}"
             + ".unclear .chip{background:#fffaeb;color:#b54708;}"
             + "pre{background:#fff;border:1px solid #e4e7ec;border-radius:10px;padding:12px 14px;"
             + "font:12px/1.6 'Cascadia Mono',Consolas,monospace;white-space:pre-wrap;}"
             + "code{font-family:'Cascadia Mono',Consolas,monospace;background:#f2f4f7;"
             + "padding:1px 5px;border-radius:4px;}"
             + ".fine{color:#667085;font-size:12.5px;}"
             + "ul{margin:6px 0 0 18px;padding:0;}li{margin-bottom:5px;}";
    }
}

// --------------------------------------------------------------------------
// lib/UlChoices.java
// --------------------------------------------------------------------------

/**
 * The one place where the SDK's own enums meet this tool's plain integers.
 *
 * Why it exists rather than a handful of strings in the dialog:
 *
 *   * The three axes an MSL is made of are the same three the SDK already names
 *     - IntegrityLevel, CipherMode, CounterMode. Driving the dropdowns from
 *     those enums means the choices offered are exactly the choices the SDK can
 *     act on, and a value that stops existing in a future SDK becomes a compile
 *     error here instead of a run that quietly does the wrong thing.
 *
 *   * MslCore has to stay free of SDK imports - it is the file the self-test and
 *     the Python port mirror, and it must compile and be checkable without the
 *     platform. So the conversion lives here, in one direction each way, with a
 *     round-trip test over every value rather than a comment claiming it works.
 *
 *   * SPI bit packing stops being this tool's problem. MslCore.spiFirstOctet()
 *     still computes the byte for the card-free logic, but what the probe script
 *     actually sends is built by the SDK's own typed SPI constructor - and
 *     MslSelfTest asserts the two agree for all 32 combinations, which is what
 *     makes it safe to have both.
 *
 * Verified against the 3.8.0 Javadoc, not inferred from the names: every
 * constant used below appears in the enum constant summary of its class, and
 * the SPI constructor used is the five-argument SMS-delivery one.
 */
final class UlChoices
{
    private UlChoices() { }

    // ------------------------------------------------------------------
    // Integrity - SPI octet 1, bits b2 b1
    // ------------------------------------------------------------------

    /** Every integrity level, in the order the MSL axis orders them. */
    public static final IntegrityLevel[] INTEGRITY = {
        IntegrityLevel.NONE,
        IntegrityLevel.REDUNDANCY_CHECK,
        IntegrityLevel.CRYPTOGRAPHIC_CHECKSUM,
        IntegrityLevel.DIGITAL_SIGNATURE,
    };

    public static IntegrityLevel integrity(int axisValue)
    {
        return INTEGRITY[check(axisValue, INTEGRITY.length, "integrity")];
    }

    public static int integrityValue(IntegrityLevel level)
    {
        for (int i = 0; i < INTEGRITY.length; i++)
        {
            if (INTEGRITY[i] == level) { return i; }
        }
        throw new IllegalArgumentException("unmapped IntegrityLevel: " + level);
    }

    // ------------------------------------------------------------------
    // Ciphering - SPI octet 1, bit b3
    // ------------------------------------------------------------------

    public static final CipherMode[] CIPHER = { CipherMode.OFF, CipherMode.ON };

    public static CipherMode cipher(int axisValue)
    {
        return CIPHER[check(axisValue, CIPHER.length, "ciphering")];
    }

    public static int cipherValue(CipherMode mode)
    {
        return mode == CipherMode.ON ? MslCore.CIPHER_ON : MslCore.CIPHER_OFF;
    }

    // ------------------------------------------------------------------
    // Counter policy - SPI octet 1, bits b5 b4
    // ------------------------------------------------------------------

    public static final CounterMode[] COUNTER = {
        CounterMode.NO_COUNTER,
        CounterMode.AVAILABLE_NO_CHECKING,
        CounterMode.PROCESS_IF_HIGHER,
        CounterMode.PROCESS_IF_ONE_HIGHER,
    };

    public static CounterMode counter(int axisValue)
    {
        return COUNTER[check(axisValue, COUNTER.length, "counter")];
    }

    public static int counterValue(CounterMode mode)
    {
        for (int i = 0; i < COUNTER.length; i++)
        {
            if (COUNTER[i] == mode) { return i; }
        }
        throw new IllegalArgumentException("unmapped CounterMode: " + mode);
    }

    // ------------------------------------------------------------------
    // The whole SPI, built by the SDK rather than packed here
    // ------------------------------------------------------------------

    /**
     * The two SPI bytes for one probe, built through the SDK's typed
     * constructor.
     *
     * The alternative - shifting bits into an int by hand - is the single
     * easiest thing in this whole tool to get quietly wrong, and a wrong SPI
     * does not look like a wrong SPI: it looks like a card that rejects
     * everything, which is exactly the answer this tool is supposed to be able
     * to trust.
     */
    public static SPI spi(int integrityAxis, int cipherAxis, int counterAxis,
                          PoRMode porMode, PoRSMSType porSmsType)
    {
        return new SPI(integrity(integrityAxis), cipher(cipherAxis), counter(counterAxis),
                       porMode, porSmsType);
    }

    /** The same SPI as a plain 0..FFFF int, which is what SCP80SecurityParameters takes. */
    public static int spiValue(int integrityAxis, int cipherAxis, int counterAxis,
                               PoRMode porMode, PoRSMSType porSmsType)
    {
        byte[] bytes = spi(integrityAxis, cipherAxis, counterAxis, porMode, porSmsType)
            .toByteArray();

        if (bytes == null || bytes.length != 2)
        {
            throw new IllegalStateException("the SDK returned "
                + (bytes == null ? "no" : String.valueOf(bytes.length))
                + " SPI byte(s); two were expected");
        }
        return ((bytes[0] & 0xFF) << 8) | (bytes[1] & 0xFF);
    }

    // ------------------------------------------------------------------
    // Values offered in the dropdowns
    // ------------------------------------------------------------------

    /**
     * The SCP02 security levels the SDK defines, straight from the enum.
     *
     * Taken from values() rather than typed out so the list cannot drift from
     * the SDK. R-MAC levels are offered because the enum has them; whether a
     * given card supports one is a card question, and the run says so plainly
     * if it does not.
     */
    public static SecurityLevel[] securityLevels()
    {
        return SecurityLevel.values();
    }

    public static PoRMode[] porModes()
    {
        return PoRMode.values();
    }

    public static PoRSMSType[] porSmsTypes()
    {
        return PoRSMSType.values();
    }

    /** Parses a security level name back, falling back to CMAC - the widest supported. */
    public static SecurityLevel securityLevel(String name)
    {
        SecurityLevel[] all = SecurityLevel.values();
        for (int i = 0; i < all.length; i++)
        {
            if (all[i].name().equalsIgnoreCase(name)) { return all[i]; }
        }
        return SecurityLevel.CMAC;
    }

    public static PoRMode porMode(String name)
    {
        PoRMode[] all = PoRMode.values();
        for (int i = 0; i < all.length; i++)
        {
            if (all[i].name().equalsIgnoreCase(name)) { return all[i]; }
        }
        return PoRMode.POR_REQUIRED;
    }

    public static PoRSMSType porSmsType(String name)
    {
        PoRSMSType[] all = PoRSMSType.values();
        for (int i = 0; i < all.length; i++)
        {
            if (all[i].name().equalsIgnoreCase(name)) { return all[i]; }
        }
        return PoRSMSType.SMS_DELIVER_REPORT;
    }

    private static int check(int value, int count, String axis)
    {
        if (value < 0 || value >= count)
        {
            throw new IllegalArgumentException(axis + " value out of range: " + value);
        }
        return value;
    }
}

// --------------------------------------------------------------------------
// lib/MslConfig.java
// --------------------------------------------------------------------------

/**
 * Everything a run needs, as typed into the run dialog.
 *
 * Nothing in here is ever read from a file. The operator swaps test SIMs
 * between runs, and a value that persists across a card swap is a value that
 * gets sent to the wrong card - so keys, AIDs and counters are typed fresh
 * every run and live only for the length of it. The only thing loaded from disk
 * is the optional non-secret pre-fill in config/msl.properties, which exists so
 * nobody retypes an ISD AID forty times, and which never carries key material.
 *
 * validate() returns the list of things that would stop the run. The dialog
 * keeps the Start button disabled while that list is non-empty, which is how
 * "nothing is sent before the operator confirms" is actually enforced.
 */
final class MslConfig
{
    public static final int SCOPE_INSTALL = 1;
    public static final int SCOPE_PROBE = 2;

    public static final int MODE_VERIFY = 1;
    public static final int MODE_DISCOVER = 2;
    public static final int MODE_INSTALL = 3;
    public static final int MODE_OTA_INSTALL = 4;
    public static final int MODE_BROWSE = 5;
    public static final int MODE_DELETE = 6;

    /** Which road a card content management job takes to the card. */
    public static final int TRANSPORT_OTA = 0;      // secured packets to the card manager TAR
    public static final int TRANSPORT_ISD = 1;      // an SCP02 secure channel over the contact

    /**
     * Which of the jobs this run does.
     *
     * The mode, not the scope, is what decides which values a run needs. There
     * is one script now - card content management and OTA probing in the same
     * class - so a fixed scope per script no longer exists to branch on.
     */
    public static boolean isInstall(int mode) { return mode == MODE_INSTALL; }

    /**
     * True for a job that changes what is on the card and cannot be undone.
     *
     * The dialog requires a second, separate acknowledgement for every one of
     * these, and the scripts refuse to send until it is given. Probing and
     * browsing are not here: they move the OTA counter (probing) or read the
     * registry (browsing), and neither installs, deletes or overwrites.
     */
    public static boolean changesCard(int mode)
    {
        return mode == MODE_INSTALL || mode == MODE_OTA_INSTALL || mode == MODE_DELETE;
    }

    /** True for a job that talks to the card over OTA rather than through SCP02. */
    public boolean usesOta()
    {
        if (mode == MODE_DISCOVER || mode == MODE_VERIFY || mode == MODE_OTA_INSTALL)
        {
            return true;
        }
        return (mode == MODE_BROWSE || mode == MODE_DELETE) && transport == TRANSPORT_OTA;
    }

    /** True for a job that opens an SCP02 secure channel to the ISD. */
    public boolean usesSecureChannel()
    {
        if (mode == MODE_INSTALL) { return true; }

        return (mode == MODE_BROWSE || mode == MODE_DELETE) && transport == TRANSPORT_ISD;
    }

    private final int scope;

    // -- common ---------------------------------------------------------
    public String cardLabel = "";
    public String operator = "";

    // -- install: GlobalPlatform ----------------------------------------
    public byte[] isdAid = new byte[0];
    public int scp02Kvn = 0x01;
    public byte[] scp02Enc = new byte[0];
    public byte[] scp02Mac = new byte[0];
    public byte[] scp02Dek = new byte[0];
    public String scp02SecurityLevel = "CMAC";

    // -- install: what to install ---------------------------------------
    public String capPath = "";                  // optional: load the CAP first if the ELF is absent
    public byte[] loadFileAid = new byte[0];
    public byte[] moduleAid = new byte[0];
    public byte[] instanceAid = new byte[0];
    public byte[] privileges = new byte[] { 0x00 };
    public boolean deleteExistingInstance;
    public boolean makeSelectable = true;

    /**
     * Build the INSTALL APDU from MslCore instead of the SDK's typed command.
     *
     * The SDK's InstallForInstallAndMakeSelectableCommand.parameters(byte[]) is
     * documented as "the install parameters", and this tool passes the whole
     * field - C9, then EA/CA - on that reading. If a card answers 6A80 to a
     * parameters block that reads correctly in the preview, the other reading
     * (that the SDK wraps what it is given in C9 itself, so it wants only the
     * inner value) is the thing to test next, and this switch is how: MslCore
     * builds the command byte for byte and it goes out through the same secure
     * channel as a generic APDU.
     */
    public boolean buildInstallApduLocally;

    // -- install: the MSL and the rest of the toolkit parameters --------
    public MslCore.Level msl;
    public final List tars = new ArrayList();    // byte[3] each
    public int priority = 0x01;
    public int maxTimers = 0x00;
    public int maxMenuTextLength = 0x00;
    public int maxChannels = 0x00;
    public byte[] rawInstallParameters;          // non-null: use verbatim, skip the builder
    public int installFormat = MslCore.FORMAT_UICC;   // EA{80} UICC vs EF{CA} SIM (TS 102 226)

    // -- OTA card content management (RAM) -------------------------------

    /**
     * The card manager's TAR, which is where a secured packet carrying an
     * INSTALL, a GET STATUS or a DELETE has to be addressed.
     *
     * 000000 on every card this tool has met, and confirmed reachable on the
     * MCI/Hamrah card with the KVN 01 key set (GET STATUS answered PoR 00). It
     * is still a field rather than a constant because it is issuer-assigned
     * like any other TAR.
     */
    public byte[] ramTar = new byte[] { 0x00, 0x00, 0x00 };

    /**
     * Bytes of load file per LOAD command.
     *
     * Over OTA every APDU has to fit one SMS-PP envelope once the secured
     * packet, the UDH, the TPDU and the CAT envelope are wrapped around it, so
     * this is far below the 255 a contact channel allows. Raising it past
     * MslCapLoad.MAX_OTA_APDU does not make the load faster, it makes the
     * packets undeliverable.
     */
    public int loadBlockSize = MslCapLoad.DEFAULT_BLOCK_SIZE;

    /**
     * Install the applet with empty application parameters and no toolkit block.
     *
     * A plain Java Card applet - one extending javacard.framework.Applet rather
     * than being a toolkit application - has no MSL and no TAR, and a card
     * rejects a toolkit block it has no business with. The operator's
     * MobilePaymentApplet is exactly this case.
     */
    public boolean plainApplet;

    /** OTA or SCP02, for browse and delete. Install is SCP02; ota-install is OTA. */
    public int transport = TRANSPORT_OTA;

    // -- browse ----------------------------------------------------------

    public boolean browseApplications = true;      // GET STATUS P1 40
    public boolean browseLoadFiles = true;         // GET STATUS P1 10, with modules
    public boolean browseIssuerSecurityDomain;     // GET STATUS P1 80

    // -- delete ----------------------------------------------------------

    public byte[] deleteAid = new byte[0];

    /**
     * DELETE with P2 80 - the object and every object related to it.
     *
     * For a package that still has instances this is the only thing that works,
     * and it takes those instances with it. Off by default, and the script
     * lists what it is about to remove before it sends.
     */
    public boolean deleteRelatedObjects;

    /** The operator's explicit go-ahead for an irreversible job. */
    public boolean confirmIrreversible;

    // -- probing: the OTA key set ---------------------------------------
    public byte[] targetTar = new byte[0];
    public int otaKvn = 0x01;
    public String otaAlgorithm = "3des2";
    public byte[] otaKey = new byte[0];       // KID (integrity) key; also KIc when otaKicKey is empty
    public byte[] otaKicKey = new byte[0];    // KIc (ciphering) key; independent of KID, defaults to it

    /**
     * The KIc (ciphering) key actually used. KIc and KID are independent values
     * (TS 102 225), often but not always equal within a key set; otaKey carries
     * KID, and this returns the separate KIc when one was given, else KID.
     */
    public byte[] effectiveKicKey() { return otaKicKey.length > 0 ? otaKicKey : otaKey; }
    public long startCounter;
    /**
     * SPI octet 2. Set by the dialog from the two dropdowns below through the
     * SDK's own SPI constructor rather than typed as hex, so the bits are
     * packed by the library that reads them back.
     */
    public int spiSecondOctet = 0x09;            // PoR required, SMS-DELIVER-REPORT
    public String porMode = "POR_REQUIRED";      // aspects...scp80.PoRMode name
    public String porSmsType = "SMS_DELIVER_REPORT";   // aspects...scp80.PoRSMSType name
    public boolean sendTerminalProfile = true;

    /** Where the HTML and CSV report go. Empty means write none. */
    public String reportFolder = "";
    public boolean writeReport = true;
    public byte[] terminalProfile = new byte[] { 0x02 };

    // -- probing: what to prove -----------------------------------------
    public int mode = MODE_DISCOVER;          // set from the dialog's job dropdown
    public MslCore.Level claimedMsl;
    public int probeBudget = 24;
    public boolean allowCiphering;
    public boolean allowOneHigher;
    public boolean silentDrop;    // card discards below-MSL packets with no PoR instead of 0A

    public MslConfig(int scope)
    {
        this.scope = scope;
    }

    public int getScope() { return scope; }

    /**
     * The strongest packet this run can build.
     *
     * Ciphering is off unless the operator confirms the key set can do it, and
     * "counter exactly one higher" is off unless they confirm they know the
     * card's counter - because a probe that fails for a reason unrelated to the
     * MSL is worse than a probe not sent.
     */
    public MslProbing.Ceiling ceiling()
    {
        return new MslProbing.Ceiling(
            MslCore.INTEGRITY_CC,
            allowCiphering ? MslCore.CIPHER_ON : MslCore.CIPHER_OFF,
            allowOneHigher ? MslCore.COUNTER_ONE_HIGHER : MslCore.COUNTER_HIGHER);
    }

    /** The toolkit parameters block this run would install. */
    public MslCore.Toolkit toolkit()
    {
        MslCore.Toolkit toolkit = new MslCore.Toolkit(msl);
        toolkit.priority = priority;
        toolkit.maxTimers = maxTimers;
        toolkit.maxMenuTextLength = maxMenuTextLength;
        toolkit.maxChannels = maxChannels;
        for (int i = 0; i < tars.size(); i++)
        {
            toolkit.addTar((byte[]) tars.get(i));
        }
        return toolkit;
    }

    /** The install parameters field, either built from the fields or taken verbatim. */
    public byte[] installParameters()
    {
        if (rawInstallParameters != null && rawInstallParameters.length > 0)
        {
            return rawInstallParameters;
        }
        if (plainApplet)
        {
            // Just the mandatory empty C9: no toolkit block, because a plain
            // applet has no MSL and no TAR, and a card asked to accept a
            // toolkit block for one answers 6A80.
            return MslCore.buildInstallParameters(null, null, null, installFormat);
        }
        return MslCore.buildInstallParameters(toolkit(), null, null, installFormat);
    }

    /**
     * The security every RAM packet in a run is built at: cryptographic
     * checksum, no ciphering, counter higher.
     *
     * Not configurable, and deliberately so. A RAM packet carries a real card
     * content management command, so unlike a probe it has to be a packet the
     * card will actually act on: no integrity means no MAC to authenticate the
     * command manager with, and the card manager's own MSL would reject it.
     * The counter policy follows the operator's one-higher choice only because
     * that is the same decision the probing jobs make.
     */
    public MslProbing.Probe ramProbe()
    {
        return new MslProbing.Probe(MslCore.INTEGRITY_CC, MslCore.CIPHER_OFF,
            allowOneHigher ? MslCore.COUNTER_ONE_HIGHER : MslCore.COUNTER_HIGHER);
    }

    /** The GET STATUS scopes a browse run should ask for, in order. */
    public List browseScopes()
    {
        List scopes = new ArrayList();
        if (browseIssuerSecurityDomain)
        {
            scopes.add(Integer.valueOf(MslCore.STATUS_ISSUER_SECURITY_DOMAIN));
        }
        if (browseApplications)
        {
            scopes.add(Integer.valueOf(MslCore.STATUS_APPLICATIONS));
        }
        if (browseLoadFiles)
        {
            // P1 10 rather than 20: the same load files, plus the module AIDs
            // inside each - and the module AID is exactly what an INSTALL needs
            // and what nobody can read off a CAP they do not have.
            scopes.add(Integer.valueOf(MslCore.STATUS_LOAD_FILES_AND_MODULES));
        }
        return scopes;
    }

    public List validate()
    {
        List problems = new ArrayList();

        if (cardLabel.trim().length() == 0)
        {
            problems.add("Give the card a label - it goes on the certificate and is how a report "
                         + "is matched to the SIM it came from.");
        }

        if (writeReport)
        {
            if (reportFolder == null || reportFolder.trim().length() == 0)
            {
                problems.add("Choose a folder for the report, or clear the report checkbox. A "
                             + "run whose only record is a log window is a run nobody can "
                             + "review afterwards.");
            }
            else if (!new java.io.File(reportFolder).isDirectory())
            {
                problems.add("The report folder does not exist: " + reportFolder);
            }
        }

        if (mode == MODE_INSTALL)          { validateInstall(problems); }
        else if (mode == MODE_OTA_INSTALL) { validateOtaInstall(problems); }
        else if (mode == MODE_BROWSE)      { validateBrowse(problems); }
        else if (mode == MODE_DELETE)      { validateDelete(problems); }
        else                               { validateProbe(problems); }

        return problems;
    }

    private void validateInstall(List problems)
    {
        validateSecureChannel(problems);

        if (loadFileAid.length < 5) { problems.add("The executable load file AID is required."); }
        if (moduleAid.length < 5) { problems.add("The executable module AID is required."); }
        if (instanceAid.length < 5) { problems.add("The application instance AID is required."); }
        validatePrivileges(problems);
        validateInstallParameters(problems);
    }

    private void validateSecureChannel(List problems)
    {
        if (isdAid.length < 5) { problems.add("The ISD AID is required (5 to 16 bytes)."); }
        if (scp02Enc.length != 16) { problems.add("The SCP02 ENC key must be 16 bytes."); }
        if (scp02Mac.length != 16) { problems.add("The SCP02 MAC key must be 16 bytes."); }
        if (scp02Dek.length != 16) { problems.add("The SCP02 DEK key must be 16 bytes."); }
    }

    private void validatePrivileges(List problems)
    {
        if (privileges.length != 1 && privileges.length != 3)
        {
            problems.add("Privileges are 1 byte (GlobalPlatform 2.1) or 3 bytes (2.2+).");
        }
    }

    private void validateInstallParameters(List problems)
    {
        if (plainApplet && (rawInstallParameters == null || rawInstallParameters.length == 0))
        {
            // A plain applet installs with the mandatory empty C9 and nothing
            // else, so there is no MSL and no TAR to check for.
            return;
        }

        if (rawInstallParameters == null || rawInstallParameters.length == 0)
        {
            if (msl == null)
            {
                problems.add("Set the MSL to install, or tick 'install no MSL field at all', or "
                             + "paste a raw install parameters field.");
            }
            if (tars.isEmpty())
            {
                problems.add("At least one TAR is required: without one the applet is not "
                             + "reachable over OTA, and its MSL can never be exercised.");
            }
        }
        else
        {
            // A pasted field is used verbatim, so the least this tool can do is
            // say what it thinks is in it before anything is sent.
            //
            // The remainder check has to come first. The TLV walk is tolerant by
            // design and a truncated block simply parses to "no MSL declared" -
            // which is a legal thing for a block to say, so without this the
            // malformed field would be sent with no complaint at all.
            int remainder = MslCore.tlvRemainder(rawInstallParameters);
            if (remainder > 0)
            {
                problems.add("The raw install parameters do not parse: " + remainder
                             + " trailing byte(s) are not a complete TLV. Nothing will be sent "
                             + "until the whole field reads as tag-length-value to its end.");
            }
            else
            {
                try
                {
                    MslCore.mslOfInstallParameters(rawInstallParameters);
                }
                catch (RuntimeException e)
                {
                    problems.add("The raw install parameters do not parse: " + e.getMessage());
                }
            }
        }
    }

    private void validateProbe(List problems)
    {
        if (targetTar.length != 3) { problems.add("The target TAR is exactly 3 bytes."); }
        validateOtaKeySet(problems);

        if (mode == MODE_VERIFY && claimedMsl == null)
        {
            problems.add("Verifying needs the MSL the applet is supposed to have. If you do not "
                         + "know it, run in discover mode instead.");
        }
        if (probeBudget < 4)
        {
            problems.add("A probe budget below 4 cannot complete even the shortest walk.");
        }
        if (allowCiphering && effectiveKicKey().length == 0)
        {
            problems.add("Ciphered probes need the KIc key (fill KIc, or KID when they are equal).");
        }
    }

    /**
     * The key set, counter and PoR policy every OTA job needs, whatever it then
     * does with the packet.
     *
     * Shared by probing, ota-install and the OTA road into browse and delete:
     * the packet is built identically for all of them, so a key or counter that
     * would sink a probe sinks a RAM command for exactly the same reason.
     */
    private void validateOtaKeySet(List problems)
    {
        if (otaKey.length == 0) { problems.add("The OTA KIc/KID key value is required."); }

        int expected = "des".equals(otaAlgorithm) ? 8 : ("3des3".equals(otaAlgorithm) ? 24 : 16);
        if ("aes".equals(otaAlgorithm))
        {
            if (otaKey.length != 16 && otaKey.length != 24 && otaKey.length != 32)
            {
                problems.add("An AES key is 16, 24 or 32 bytes.");
            }
        }
        else if (otaKey.length != 0 && otaKey.length != expected)
        {
            problems.add("A " + otaAlgorithm + " key is " + expected + " bytes; this one is "
                         + otaKey.length + ".");
        }

        if (startCounter <= 0)
        {
            problems.add("A starting counter is required, and it must be ABOVE the card's stored "
                         + "value - too low and no PoR comes back at all, which looks exactly "
                         + "like a wrong key.");
        }

        if ((spiSecondOctet & 0x03) == 0x00)
        {
            problems.add("SPI octet 2 asks for no PoR. Every answer this tool reads is a PoR, so "
                         + "the run would produce nothing. Use 09 (PoR required, "
                         + "SMS-DELIVER-REPORT) unless the profile says otherwise.");
        }
        if ((spiSecondOctet & 0x10) != 0)
        {
            problems.add("SPI octet 2 asks for a ciphered PoR. The response status code cannot be "
                         + "read until the PoR is deciphered, which this tool does not do - clear "
                         + "bit b5.");
        }
    }

    /**
     * ota-install: load a CAP and install from it, all over OTA.
     *
     * The load file AID is NOT asked for here - it is read out of the CAP's own
     * Header component, and MslScript cross-checks that reading against the
     * SDK's LoadSequence before it sends anything. Asking the operator to retype
     * an AID the file already carries would only create a way for the two to
     * disagree.
     */
    private void validateOtaInstall(List problems)
    {
        if (capPath == null || capPath.trim().length() == 0)
        {
            problems.add("Name the CAP file to load: ota-install loads the package and installs "
                         + "from it in one run, so there is nothing to install without one.");
        }
        else if (!new java.io.File(capPath.trim()).isFile())
        {
            problems.add("No CAP file at " + capPath.trim());
        }

        if (moduleAid.length < 5)
        {
            problems.add("The executable module AID is required. The CAP's Applet component "
                         + "declares it - the run prints every AID it finds before it sends.");
        }
        if (instanceAid.length < 5) { problems.add("The application instance AID is required."); }
        validatePrivileges(problems);
        validateInstallParameters(problems);

        if (ramTar.length != 3)
        {
            problems.add("The card manager TAR is exactly 3 bytes (000000 on every card this "
                         + "tool has met).");
        }
        if (loadBlockSize < 16 || loadBlockSize > MslCapLoad.MAX_OTA_APDU - 5)
        {
            problems.add("The LOAD block size must be between 16 and "
                         + (MslCapLoad.MAX_OTA_APDU - 5) + " bytes: above that the secured packet "
                         + "no longer fits a single SMS-PP envelope and the card never sees it.");
        }
        validateOtaKeySet(problems);
    }

    /** browse: read the registry. Read-only on either road. */
    private void validateBrowse(List problems)
    {
        if (!browseApplications && !browseLoadFiles && !browseIssuerSecurityDomain)
        {
            problems.add("Choose at least one thing to list - applications, load files, or the "
                         + "issuer security domain.");
        }
        validateContentManagementTransport(problems);
    }

    /** delete: remove an instance or a package. Irreversible on either road. */
    private void validateDelete(List problems)
    {
        if (deleteAid.length < 5 || deleteAid.length > 16)
        {
            problems.add("The AID to delete is required (5 to 16 bytes). Run the browse job first "
                         + "if you are not certain of it - a DELETE sent at the wrong AID is not "
                         + "undone by noticing afterwards.");
        }
        validateContentManagementTransport(problems);
    }

    private void validateContentManagementTransport(List problems)
    {
        if (transport == TRANSPORT_ISD)
        {
            validateSecureChannel(problems);
            return;
        }

        if (ramTar.length != 3)
        {
            problems.add("The card manager TAR is exactly 3 bytes (000000 on every card this "
                         + "tool has met).");
        }
        validateOtaKeySet(problems);
    }

    /** A one-line summary for the certificate. Never includes key material. */
    public String describeForCertificate()
    {
        StringBuilder text = new StringBuilder();
        text.append("card=").append(cardLabel);
        if (operator.trim().length() > 0) { text.append(", operator=").append(operator); }

        if (mode == MODE_INSTALL)
        {
            text.append(", ISD=").append(MslCore.hex(isdAid));
            text.append(", KVN=").append(MslCore.hexByte(scp02Kvn));
            text.append(", instance=").append(MslCore.hex(instanceAid));
            text.append(", MSL=").append(msl == null ? "none" : msl.describe());
            text.append(", install parameters=").append(MslCore.hex(installParameters()));
        }
        else if (mode == MODE_OTA_INSTALL)
        {
            text.append(", job=ota-install over RAM TAR=").append(MslCore.hex(ramTar));
            text.append(", key set KVN=").append(MslCore.hexByte(otaKvn));
            text.append(" ").append(otaAlgorithm);
            text.append(", CAP=").append(capPath);
            text.append(", instance=").append(MslCore.hex(instanceAid));
            text.append(", module=").append(MslCore.hex(moduleAid));
            text.append(", LOAD block=").append(loadBlockSize);
            text.append(plainApplet ? ", plain applet (empty C9)"
                                    : ", MSL=" + (msl == null ? "none" : msl.describe()));
            text.append(", install parameters=").append(MslCore.hex(installParameters()));
        }
        else if (mode == MODE_BROWSE || mode == MODE_DELETE)
        {
            text.append(", job=").append(mode == MODE_BROWSE ? "browse" : "delete");
            if (transport == TRANSPORT_ISD)
            {
                text.append(" over SCP02, ISD=").append(MslCore.hex(isdAid));
                text.append(", KVN=").append(MslCore.hexByte(scp02Kvn));
            }
            else
            {
                text.append(" over RAM, TAR=").append(MslCore.hex(ramTar));
                text.append(", key set KVN=").append(MslCore.hexByte(otaKvn));
                text.append(" ").append(otaAlgorithm);
            }
            if (mode == MODE_DELETE)
            {
                text.append(", AID=").append(MslCore.hex(deleteAid));
                text.append(deleteRelatedObjects ? ", WITH related objects" : ", that object only");
            }
            else
            {
                text.append(", scopes=").append(browseScopes().size());
            }
        }
        else
        {
            text.append(", TAR=").append(MslCore.hex(targetTar));
            text.append(", key set KVN=").append(MslCore.hexByte(otaKvn));
            text.append(" ").append(otaAlgorithm);
            text.append(", mode=").append(mode == MODE_VERIFY ? "verify" : "discover");
            if (mode == MODE_VERIFY && claimedMsl != null)
            {
                text.append(", claimed MSL=").append(claimedMsl.describe());
            }
            text.append(", PoR=").append(porMode).append("/").append(porSmsType);
            text.append(", ceiling=").append(ceiling().describe());
        }
        return text.toString();
    }

    /** KIc/KID byte: key version in the high nibble, algorithm in the low. */
    public int otaKeyHeader()
    {
        int algorithmBits;
        if ("des".equals(otaAlgorithm))        { algorithmBits = 0x1; }
        else if ("3des3".equals(otaAlgorithm)) { algorithmBits = 0x9; }
        else if ("aes".equals(otaAlgorithm))   { algorithmBits = 0x2; }
        else                                   { algorithmBits = 0x5; }   // 3des2

        return ((otaKvn & 0x0F) << 4) | algorithmBits;
    }
}

// --------------------------------------------------------------------------
// lib/MslConfigDialog.java
// --------------------------------------------------------------------------

/**
 * The run dialog: the only place a card-specific value enters this tool.
 *
 * Built to the same pattern as the ECI file-lifecycle dialog, because that
 * pattern earned it - tabs in scroll panes so a long tab cannot hide its own
 * controls, a titled group per subject, the long reasoning attached to the
 * control it is about as a tooltip rather than printed beside it, a live list of
 * everything still wrong, and a Start button that stays disabled until that list
 * is empty.
 *
 * Two things it does differently, both on purpose:
 *
 *   * Every value drawn from a fixed set is a dropdown, and where the SDK
 *     already names that set the dropdown is filled from the SDK's own enum -
 *     IntegrityLevel, CipherMode, CounterMode, PoRMode, PoRSMSType,
 *     SecurityLevel. Nothing here types those names out. See UlChoices.
 *
 *   * The MSL is not typed as a hex byte. It is chosen on the three axes it is
 *     actually made of, and the byte is shown back as it is built. Typing 1A
 *     when 12 was meant is a one-character mistake that installs an applet
 *     enforcing something nobody asked for, and no command reads it back
 *     afterwards to catch it.
 *
 * A window rather than a modal dialog, for one concrete reason: a JDialog has
 * only a close button, and this form is long enough that an operator wants to
 * maximise it, or push it aside while reading a card profile. A JFrame gets the
 * minimise and maximise buttons the window manager provides. The blocking that
 * a modal dialog gave for free is done explicitly instead, with a latch the
 * script thread waits on - the same arrangement the ECI lifecycle dialog uses.
 *
 * The ordering rule the class exists to enforce: start the script, show this,
 * operator confirms, and only then does the script send its first byte. Cancel,
 * and closing the window, both mean send nothing at all - not even a reset.
 */
final class MslConfigDialog extends JFrame
{
    private static final long serialVersionUID = 1L;
    private static final int TEXT_WIDTH = 520;

    /** Every text field and dropdown gets this width, so the columns line up. */
    private static final int FIELD_WIDTH = 300;

    private final MslConfig config;
    private final MslProfile profile = MslProfile.load();
    private final int scope;

    /** Released when the operator confirms, cancels, or closes the window. */
    private final CountDownLatch done = new CountDownLatch(1);

    private boolean confirmed;

    // -- job ------------------------------------------------------------
    private final JComboBox modeCombo = new JComboBox(new String[] {
        "discover - find the MSL an installed applet enforces",
        "verify - prove a known MSL is the one in force",
        "install - put an applet on the card with a chosen MSL (SCP02)",
        "ota-install - load a CAP and install from it over OTA (irreversible)",
        "browse - list the applets and packages on the card (read-only)",
        "delete - remove an applet instance or a package (irreversible)" });
    private final JLabel jobSteps = new JLabel();
    private final JTextField cardLabelField = new JTextField(20);
    private final JTextField operatorField = new JTextField(20);

    // -- GlobalPlatform --------------------------------------------------
    // Real ISD/Card-Manager AIDs from the operator's profile docs: profile B
    // ("updated TAR List") uses A000000151000000, the earlier MCI card used
    // A000000003000000 (the 151 value returned 6A82 there). Pick per card.
    private final JComboBox isdAidCombo = editable(new String[] {
        "A000000151000000", "A000000003000000", "A0000001515350", "A0000000030000" });
    // Profile A ISD key set = 70; profile B GP key version = 20.
    private final JComboBox scp02KvnCombo = editable(new String[] { "20", "70", "01", "02", "FF" });
    private final JPasswordField scp02EncField = new JPasswordField(34);
    private final JPasswordField scp02MacField = new JPasswordField(34);
    private final JPasswordField scp02DekField = new JPasswordField(34);
    private final JComboBox securityLevelCombo = new JComboBox(UlChoices.securityLevels());

    // -- applet ----------------------------------------------------------
    private final JTextField capPathField = new JTextField(30);
    private final JButton capBrowseButton = new JButton("Browse...");
    private final JTextField loadFileAidField = new JTextField(24);
    private final JTextField moduleAidField = new JTextField(24);
    private final JTextField instanceAidField = new JTextField(24);
    private final JComboBox privilegesCombo = editable(new String[] {
        "00", "80", "C0", "000000", "800000" });
    private final JCheckBox deleteExistingCheck = new JCheckBox(
        "DELETE any instance with this AID first");
    private final JCheckBox makeSelectableCheck = new JCheckBox(
        "INSTALL [for install and make selectable]", true);
    private final JCheckBox localApduCheck = new JCheckBox(
        "Build the INSTALL APDU here instead of using the SDK command object");

    // -- MSL -------------------------------------------------------------
    private final JComboBox mslIntegrityCombo = new JComboBox(UlChoices.INTEGRITY);
    private final JComboBox mslCipherCombo = new JComboBox(UlChoices.CIPHER);
    private final JComboBox mslCounterCombo = new JComboBox(UlChoices.COUNTER);
    private final JComboBox installFormatCombo = new JComboBox(new String[] {
        "UICC  -  tag EA wrapping tag 80 (ETSI TS 102 226, UICC format)",
        "SIM   -  tag EF wrapping tag CA (ETSI TS 102 226, SIM format)" });
    private final JCheckBox noMslCheck = new JCheckBox(
        "Install no Minimum Security Level field at all (length 00)");
    private final JLabel mslReadout = new JLabel();
    // Real per-applet TARs from the MCI-14000213 profile: USIM B00011, ISIM
    // B00020, HPSIM B00021, EAP B00022, RFM B00010, RAM 000000, S@T 534054.
    private final JComboBox tarCombo = editable(new String[] {
        "B00011", "B00020", "B00021", "B00022", "B00010", "000000",
        "B0001E", "B0001F", "534054", "505348" });
    private final JTextField extraTarsField = new JTextField(24);
    private final JComboBox priorityCombo = editable(new String[] { "01", "02", "0F" });
    private final JComboBox timersCombo = editable(new String[] { "00", "01", "02", "08" });
    private final JComboBox menuTextCombo = editable(new String[] { "00", "10", "20" });
    private final JComboBox channelsCombo = editable(new String[] { "00", "01", "02", "07" });
    private final JTextField rawParamsField = new JTextField(40);
    private final JTextArea paramsPreview = new JTextArea(9, 64);

    // -- OTA -------------------------------------------------------------
    // The applet to probe. Real TARs across both profiles - RFM/USIM/ISIM/HPSIM
    // differ between cards (profile B: USIM RFM B00020, ISIM B0001E, HPSIM
    // B0001F; profile A: USIM B00011, ISIM B00020, HPSIM B00021). Pick per card.
    private final JComboBox targetTarCombo = editable(new String[] {
        "B00010", "B00011", "B00020", "B00021", "B00022",
        "B0001E", "B0001F", "000000", "534054", "505348" });
    // OTA key sets across both profiles: profile A 3DES 01/02/04/05 + AES 0B/0C;
    // profile B 01/02/03. Single DES is deliberately absent - both docs say it
    // is not supported for OTA.
    private final JComboBox otaKvnCombo = editable(new String[] {
        "01", "02", "03", "04", "05", "0B", "0C" });
    private final JComboBox otaAlgCombo = new JComboBox(new String[] {
        "3des2", "3des3", "des", "aes" });
    private final JPasswordField otaKeyField = new JPasswordField(34);     // KID (integrity)
    private final JPasswordField otaKicKeyField = new JPasswordField(34);  // KIc (ciphering)
    private final JTextField counterField = new JTextField(14);
    private final JComboBox porModeCombo = new JComboBox(UlChoices.porModes());
    private final JComboBox porSmsCombo = new JComboBox(UlChoices.porSmsTypes());
    private final JLabel spiReadout = new JLabel();
    private final JCheckBox terminalProfileCheck = new JCheckBox(
        "Send TERMINAL PROFILE before the first secured packet", true);
    private final JComboBox terminalProfileCombo = editable(new String[] { "02", "FFFF", "FF" });

    // -- probing ---------------------------------------------------------
    private final JComboBox claimedIntegrityCombo = new JComboBox(UlChoices.INTEGRITY);
    private final JComboBox claimedCipherCombo = new JComboBox(UlChoices.CIPHER);
    private final JComboBox claimedCounterCombo = new JComboBox(UlChoices.COUNTER);
    private final JLabel claimedReadout = new JLabel();
    private final JComboBox budgetCombo = editable(new String[] { "12", "18", "24", "40" });
    private final JCheckBox allowCipheringCheck = new JCheckBox(
        "Allow ciphered probes");
    private final JCheckBox allowOneHigherCheck = new JCheckBox(
        "Allow \"counter exactly one higher\" probes");
    private final JCheckBox silentDropCheck = new JCheckBox(
        "Card discards below-MSL packets silently (read a no-PoR drop as below-MSL)");

    // -- card content management ------------------------------------------
    private final JComboBox transportCombo = new JComboBox(new String[] {
        "OTA  -  secured packets to the card manager TAR (no SCP02 keys needed)",
        "SCP02 -  a secure channel to the ISD over the contact interface" });
    private final JComboBox ramTarCombo = editable(new String[] { "000000" });
    private final JComboBox blockSizeCombo = editable(new String[] { "160", "128", "96", "192" });
    private final JCheckBox plainAppletCheck = new JCheckBox(
        "Plain applet - install with empty application parameters (no MSL, no TAR)");
    private final JTextField deleteAidField = new JTextField(24);
    private final JCheckBox deleteRelatedCheck = new JCheckBox(
        "Delete related objects too (a package AND every instance made from it)");
    private final JCheckBox browseApplicationsCheck = new JCheckBox(
        "Applications and security domains (GET STATUS P1 40)", true);
    private final JCheckBox browseLoadFilesCheck = new JCheckBox(
        "Packages and the modules inside them (GET STATUS P1 10)", true);
    private final JCheckBox browseIsdCheck = new JCheckBox(
        "The issuer security domain itself (GET STATUS P1 80)");

    // -- report ----------------------------------------------------------
    private final JCheckBox writeReportCheck = new JCheckBox(
        "Write an HTML and CSV report when the run finishes", true);
    private final JTextField reportFolderField = new JTextField(30);
    private final JButton reportBrowseButton = new JButton("...");

    // -- run -------------------------------------------------------------
    private final JCheckBox matchCheck = new JCheckBox(
        "These values match the SIM currently in the reader");
    private final JCheckBox changeCheck = new JCheckBox(
        "I accept that this run changes that SIM and cannot be undone");

    private final JLabel problemsLabel = new JLabel();
    private final JButton startButton = new JButton("Start run");

    private MslConfigDialog(Frame parent, String scriptName)
    {
        super("MSL checking - run configuration - " + scriptName);
        this.scope = MslConfig.SCOPE_INSTALL;
        this.config = new MslConfig(MslConfig.SCOPE_INSTALL);

        // Closing the window is a cancel, not a silent dismissal: the script is
        // waiting on the latch and would otherwise hang forever.
        setDefaultCloseOperation(WindowConstants.DO_NOTHING_ON_CLOSE);
        addWindowListener(new WindowAdapter()
        {
            public void windowClosing(WindowEvent event) { finish(false); }
        });

        buildUi(scriptName);
        prefill();
        wireValidation();
        revalidateNow();

        pack();
        setMinimumSize(new Dimension(720, 560));
        setSize(Math.min(980, getWidth() + 40), Math.min(800, getHeight() + 20));
        setLocationRelativeTo(parent);
    }

    /** Confirm, cancel or close - all three end the same way. */
    private void finish(boolean accepted)
    {
        confirmed = accepted;
        setVisible(false);
        dispose();
        done.countDown();
    }

    /**
     * Shows the dialog and blocks until the operator confirms or cancels.
     * Returns null on cancel, which every script must treat as "send nothing".
     */
    public static MslConfig prompt(final Frame parent, final String scriptName)
    {
        final MslConfigDialog[] holder = new MslConfigDialog[1];

        // The platform's own look and feel is left exactly as it was found. It is
        // only set when nothing has chosen one, which is the case when a script
        // is run outside the GUI - the default there is Metal, which looks
        // nothing like the rest of the tool.
        String previousLaf = installNativeLookAndFeelIfUnset();

        SwingUtilities.invokeLater(new Runnable()
        {
            public void run()
            {
                holder[0] = new MslConfigDialog(parent, scriptName);
                holder[0].setVisible(true);
                holder[0].toFront();
            }
        });

        // The script runs on its own thread, so waiting here blocks the script
        // and not the interface. This is what the modal flag used to do; a
        // JFrame needs it said out loud.
        MslConfigDialog dialog;
        try
        {
            // The window is built on the event thread, so wait for it to exist
            // before waiting on its latch.
            while (holder[0] == null)
            {
                Thread.sleep(20);
            }
            dialog = holder[0];
            dialog.done.await();
        }
        catch (InterruptedException e)
        {
            Thread.currentThread().interrupt();
            restoreLookAndFeel(previousLaf);
            return null;
        }

        restoreLookAndFeel(previousLaf);
        return dialog.confirmed ? dialog.config : null;
    }

    /**
     * Returns the look and feel that was in place, or null when it was left
     * untouched. Inside the UL GUI the platform has already chosen one and this
     * does nothing at all.
     */
    private static String installNativeLookAndFeelIfUnset()
    {
        try
        {
            String current = UIManager.getLookAndFeel() == null
                ? null : UIManager.getLookAndFeel().getClass().getName();
            String cross = UIManager.getCrossPlatformLookAndFeelClassName();

            if (current != null && !current.equals(cross)) { return null; }

            UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
            return current;
        }
        catch (Exception e)
        {
            return null;
        }
    }

    private static void restoreLookAndFeel(String previous)
    {
        if (previous == null) { return; }

        try
        {
            UIManager.setLookAndFeel(previous);
        }
        catch (Exception ignored)
        {
            // Nothing to do: the run is over and the window is gone.
        }
    }

    // ==================================================================
    // Layout
    // ==================================================================

    private void buildUi(String scriptName)
    {
        JTabbedPane tabs = new JTabbedPane();

        // Every tab, every run. Which values a run actually needs is decided by
        // the job dropdown and enforced by the validation panel; hiding tabs
        // instead would mean a value set for one job vanishing when the operator
        // switches to another and back.
        tabs.addTab("Job", inScroller(buildJobTab(scriptName)));
        tabs.addTab("GlobalPlatform", inScroller(buildGpTab()));
        tabs.addTab("Applet", inScroller(buildAppletTab()));
        tabs.addTab("Card content", inScroller(buildCardContentTab()));
        tabs.addTab("Minimum Security Level", inScroller(buildMslTab()));
        tabs.addTab("OTA key set", inScroller(buildOtaTab()));
        tabs.addTab("Probing", inScroller(buildProbeTab()));
        tabs.addTab("Run", inScroller(buildRunTab()));

        problemsLabel.setForeground(new Color(150, 30, 20));
        problemsLabel.setVerticalAlignment(JLabel.TOP);

        startButton.addActionListener(new ActionListener()
        {
            public void actionPerformed(ActionEvent event) { onStart(); }
        });

        JButton cancelButton = new JButton("Cancel (send nothing)");
        cancelButton.addActionListener(new ActionListener()
        {
            public void actionPerformed(ActionEvent event) { finish(false); }
        });

        JPanel buttons = new JPanel();
        buttons.add(startButton);
        buttons.add(cancelButton);

        JPanel south = new JPanel(new BorderLayout(6, 6));
        south.add(new JScrollPane(problemsLabel), BorderLayout.CENTER);
        south.add(buttons, BorderLayout.SOUTH);
        south.setPreferredSize(new Dimension(760, 130));
        south.setMinimumSize(new Dimension(360, 80));

        JPanel content = new JPanel(new BorderLayout(8, 8));
        content.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        content.add(tabs, BorderLayout.CENTER);
        content.add(south, BorderLayout.SOUTH);
        setContentPane(content);
    }

    private JPanel buildJobTab(String scriptName)
    {
        JPanel job = group("What this run does");
        GridBagConstraints c = newConstraints();
        int row = 0;

        {
            row = addRow(job, c, row, "Job:", tip(modeCombo,
                "Discover measures each axis and reports what the card enforces, checking its own "
                + "answer afterwards. Verify starts from an MSL you already believe and proves it "
                + "in both directions: accepted at that level, rejected 0A one notch below. "
                + "Install puts an applet on the card carrying the MSL chosen on its own tab: the "
                + "MSL is a field in the INSTALL parameters, so setting one means installing, and "
                + "no command changes it afterwards."));
        }

        // Rewritten by updateReadouts() whenever the job changes: a step list
        // describing a different job than the one selected is worse than none.
        jobSteps.setForeground(new Color(50, 60, 70));
        jobSteps.setBorder(BorderFactory.createEmptyBorder(2, 2, 8, 2));
        row = wide(job, c, row, jobSteps);

        JPanel who = group("Identification");
        GridBagConstraints c2 = newConstraints();
        int row2 = 0;
        row2 = addRow(who, c2, row2, "Card label:", tip(cardLabelField,
            "Goes on the certificate. It is how a report is matched to the SIM it came from, so "
            + "make it the label on the card, not a description of the test."));
        row2 = addRow(who, c2, row2, "Operator:", tip(operatorField,
            "Optional. Recorded on the certificate alongside the card label."));

        return tabOf(new JPanel[] { job, who });
    }

    private JPanel buildGpTab()
    {
        JPanel sd = group("Issuer Security Domain");
        GridBagConstraints c = newConstraints();
        int row = 0;
        row = addRow(sd, c, row, "ISD AID:", tip(isdAidCombo,
            "The card manager's AID. If a SELECT of this answers 6A82 the AID is wrong for this "
            + "card - DiscoverSecurityDomainsScript reads the real one out of the card's own "
            + "registry rather than guessing."));
        row = addRow(sd, c, row, "Key version:", tip(scp02KvnCombo,
            "The SCP02 key set version to authenticate with. GET DATA tag E0 lists the versions a "
            + "card actually has; 6A88 from EXTERNAL AUTHENTICATE means this one is not among them."));
        row = addRow(sd, c, row, "Security level:", tip(securityLevelCombo,
            "Filled from the SDK's own SecurityLevel enum. CMAC is the level most widely "
            + "supported; R-MAC levels exist in the enum but not on every card, and one card in "
            + "this lab throws rather than refusing politely."));

        JPanel keys = group("Static keys - typed fresh every run, never loaded from a file");
        GridBagConstraints c2 = newConstraints();
        int row2 = 0;
        row2 = wide(keys, c2, row2, hint("Test SIMs get swapped between runs, and a key that "
            + "survives a card swap is a key sent to the wrong card. MslProfile drops any "
            + "key-looking entry it finds in the pre-fill file and says so."));
        row2 = addRow(keys, c2, row2, "ENC:", tip(scp02EncField, "16 bytes, hex."));
        row2 = addRow(keys, c2, row2, "MAC:", tip(scp02MacField, "16 bytes, hex."));
        row2 = addRow(keys, c2, row2, "DEK:", tip(scp02DekField, "16 bytes, hex."));

        return tabOf(new JPanel[] { sd, keys });
    }

    private JPanel buildAppletTab()
    {
        JPanel aids = group("What is being installed");
        GridBagConstraints c = newConstraints();
        int row = 0;
        row = addRow(aids, c, row, "Load file AID:", tip(loadFileAidField,
            "The executable load file (package) AID already on the card, or the one the CAP below "
            + "will load. 6A88 from INSTALL means the card does not have it."));
        row = addRow(aids, c, row, "Module AID:", tip(moduleAidField,
            "The executable module inside that load file. The CAP declares it; the registry "
            + "listing in the run log shows what the card has."));
        row = addRow(aids, c, row, "Instance AID:", tip(instanceAidField,
            "The AID the new applet instance will have. 6985 from INSTALL usually means an "
            + "instance with this AID already exists - tick the delete box or choose another."));
        row = addRow(aids, c, row, "Privileges:", tip(privilegesCombo,
            "1 byte (GlobalPlatform 2.1) or 3 (2.2+). 00 is no privileges, which is what a test "
            + "applet wants. Card lock and card terminate are privileges you can lose a card to - "
            + "do not grant them to something you are only probing."));

        JPanel cap = group("CAP file (optional)");
        GridBagConstraints c2 = newConstraints();
        int row2 = 0;
        JPanel capRow = new JPanel(new BorderLayout(6, 0));
        capRow.add(capPathField, BorderLayout.CENTER);
        capRow.add(capBrowseButton, BorderLayout.EAST);
        capBrowseButton.addActionListener(new ActionListener()
        {
            public void actionPerformed(ActionEvent event) { browseForCap(); }
        });
        row2 = addRow(cap, c2, row2, "CAP path:", tip(capRow,
            "Only used when the load file above is not already on the card. Leave it empty to "
            + "refuse rather than guess: an INSTALL against a missing package can only answer "
            + "6A88."));

        JPanel how = group("How to install");
        GridBagConstraints c3 = newConstraints();
        int row3 = 0;
        row3 = wide(how, c3, row3, tip(makeSelectableCheck,
            "Clear this for INSTALL [for install] only. The applet is then INSTALLED but not "
            + "SELECTABLE - which also makes it unreachable by its TAR, so OTA answers 09 and the "
            + "MSL can never be exercised. Useful only to test that distinction deliberately."));
        row3 = wide(how, c3, row3, tip(deleteExistingCheck,
            "An MSL cannot be changed in place. Changing one means deleting the instance and "
            + "installing it again, which is what this box is for."));
        row3 = wide(how, c3, row3, tip(localApduCheck,
            "The SDK's parameters(byte[]) is documented as \"the install parameters\" and nothing "
            + "more - the Javadoc's method detail adds no further prose, which was checked "
            + "directly. This tool passes the whole field on that reading. If a card answers 6A80 "
            + "to a block that reads correctly in the preview, tick this: the INSTALL is then "
            + "built here byte for byte and sent through the same secure channel, which localises "
            + "the disagreement."));

        return tabOf(new JPanel[] { aids, cap, how });
    }

    /**
     * Everything the three card content management jobs need: ota-install,
     * browse and delete.
     *
     * They share a tab because they share the question the tab answers - which
     * road to the card manager, and with what - and because an operator who
     * browsed to find an AID is usually about to delete or install at it.
     */
    private JPanel buildCardContentTab()
    {
        JPanel road = group("How to reach the card manager");
        GridBagConstraints c = newConstraints();
        int row = 0;
        row = wide(road, c, row, hint("Card content management is GlobalPlatform work and there "
            + "are two roads to it. OTA wraps each command in a secured packet addressed to the "
            + "card manager's TAR and needs only the OTA key set, which is the road an operator "
            + "with no ISD keys has. SCP02 opens a secure channel over the contact interface and "
            + "needs the ENC/MAC/DEK keys on the GlobalPlatform tab. ota-install is OTA by "
            + "definition; install is SCP02; browse and delete can take either."));
        row = addRow(road, c, row, "Road:", tip(transportCombo,
            "Which road browse and delete take. On the MCI/Hamrah card the OTA road is confirmed "
            + "reachable with the KVN 01 key set - GET STATUS answered PoR 00 - and no ISD keys "
            + "were ever needed."));
        row = addRow(road, c, row, "Card manager TAR:", tip(ramTarCombo,
            "Where a secured packet carrying an INSTALL, GET STATUS or DELETE is addressed. "
            + "000000 on every card this tool has met, and issuer-assigned like any other TAR."));

        JPanel load = group("ota-install: loading the CAP");
        GridBagConstraints c2 = newConstraints();
        int row2 = 0;
        row2 = wide(load, c2, row2, hint("The CAP path, module AID, instance AID and privileges "
            + "come from the Applet tab; the load file AID is NOT asked for, because the CAP's "
            + "own Header component declares it and the run cross-checks that reading against "
            + "the SDK's LoadSequence before it sends anything."));
        row2 = addRow(load, c2, row2, "LOAD block size:", tip(blockSizeCombo,
            "Bytes of load file per LOAD command, decimal. Over OTA each APDU has to fit one "
            + "SMS-PP envelope once the secured packet, the UDH, the TPDU and the CAT envelope "
            + "are wrapped around it - so this is far below the 255 a contact channel allows. "
            + "160 is the tested value; above " + (MslCapLoad.MAX_OTA_APDU - 5) + " the packets "
            + "become undeliverable rather than merely slow."));
        row2 = wide(load, c2, row2, tip(plainAppletCheck,
            "For an applet that is not a toolkit application - one extending "
            + "javacard.framework.Applet, like the operator's MobilePaymentApplet. It installs "
            + "with the mandatory empty C9 and no toolkit block at all: no MSL, no TAR. A card "
            + "sent a toolkit block for an applet that has no business with one answers 6A80."));

        JPanel browse = group("browse: what to list");
        GridBagConstraints c3 = newConstraints();
        int row3 = 0;
        row3 = wide(browse, c3, row3, hint("Read-only. Over OTA each scope costs one secured "
            + "packet and therefore one step of the OTA counter; over SCP02 it costs nothing but "
            + "the session. This is the job to run before an install or a delete - it is the only "
            + "way to learn the AIDs a card actually has."));
        row3 = wide(browse, c3, row3, tip(browseApplicationsCheck,
            "Applet instances and supplementary security domains, with their life cycle state. "
            + "Life cycle 07 is SELECTABLE; 03 is INSTALLED but not selectable, which also means "
            + "unreachable by TAR."));
        row3 = wide(browse, c3, row3, tip(browseLoadFilesCheck,
            "Packages (executable load files) and the executable modules inside each. The module "
            + "AID is what an INSTALL needs and what nobody can read off a CAP they do not have."));
        row3 = wide(browse, c3, row3, tip(browseIsdCheck,
            "The card manager's own entry and its life cycle - OP_READY, INITIALIZED, SECURED, "
            + "CARD_LOCKED or TERMINATED. Over SCP02 this one scope is sent as an APDU built by "
            + "MslCore rather than by the SDK's typed command, because the SDK constant for it is "
            + "not one this tool has verified."));

        JPanel remove = group("delete: what to remove - IRREVERSIBLE");
        GridBagConstraints c4 = newConstraints();
        int row4 = 0;
        row4 = addRow(remove, c4, row4, "AID to delete:", tip(deleteAidField,
            "An applet instance AID or a package (load file) AID. The run reads the registry "
            + "first and refuses to send when the card does not have this AID at all - a DELETE "
            + "at a mistyped AID can only answer 6A88, and hearing that before the send is the "
            + "point."));
        row4 = wide(remove, c4, row4, tip(deleteRelatedCheck,
            "DELETE with P2 80. For a package that still has instances this is the only thing "
            + "that works, and it takes those instances with it - including their install "
            + "parameters, which is where the MSL lives. The run names everything it found at "
            + "that AID before it sends."));
        row4 = wide(remove, c4, row4, hint("A deleted applet cannot be restored by this tool or "
            + "any other: the CAP can be loaded again, but the instance, its MSL and anything it "
            + "stored are gone. Prefer a disposable test card."));

        return tabOf(new JPanel[] { road, load, browse, remove });
    }

    private JPanel buildMslTab()
    {
        JPanel level = group("The Minimum Security Level to install");
        GridBagConstraints c = newConstraints();
        int row = 0;
        row = wide(level, c, row, hint("An MSL is three independent choices, not a hex byte. They "
            + "are chosen here on the SDK's own enums and the byte is shown back as it is built - "
            + "because nothing on a card reads install parameters back, so a mistyped byte is "
            + "never caught afterwards."));
        row = addRow(level, c, row, "Integrity:", tip(mslIntegrityCombo,
            "SPI octet 1, bits b2 b1. A packet applying less integrity than this is rejected 0A. "
            + "Digital signature is in the enum but neither this tool nor the SDK's "
            + "DefaultSCP80Security implements it, so an applet requiring it cannot be probed."));
        row = addRow(level, c, row, "Ciphering:", tip(mslCipherCombo,
            "SPI octet 1, bit b3. Requiring ciphering means every packet to this applet must be "
            + "enciphered, and probing it needs a KIc key the card accepts."));
        row = addRow(level, c, row, "Counter:", tip(mslCounterCombo,
            "SPI octet 1, bits b5 b4. PROCESS_IF_ONE_HIGHER is the strictest and the least "
            + "forgiving: one lost or duplicated packet desynchronises the card until the counter "
            + "is reset."));
        row = wide(level, c, row, mslReadout);
        row = addRow(level, c, row, "Parameter format:", tip(installFormatCombo,
            "How the toolkit block is wrapped. ETSI TS 102 226 defines two: UICC nests tag 80 "
            + "in tag EA, SIM nests tag CA in tag EF. The spec rejects EA+CA together with "
            + "6A80. These are modern UICCs, so UICC is the default; switch to SIM only if an "
            + "install answers 6A80 on a block that reads correctly in the preview."));
        row = wide(level, c, row, tip(noMslCheck,
            "Emits a Minimum Security Level field of length 00, which is legal and means the "
            + "applet enforces no minimum at all. Worth installing deliberately once, so the "
            + "verify job has a known negative to report."));

        JPanel tars = group("TAR");
        GridBagConstraints c2 = newConstraints();
        int row2 = 0;
        row2 = addRow(tars, c2, row2, "TAR:", tip(tarCombo,
            "The 3-byte reference the applet answers to over OTA. Issuer-assigned: the values "
            + "offered here are the ones this card family uses, not a standard. Without a TAR the "
            + "applet is unreachable over OTA and its MSL can never be exercised."));
        row2 = addRow(tars, c2, row2, "Extra TARs:", tip(extraTarsField,
            "Optional, comma separated. An applet may hold several."));

        JPanel toolkit = group("Other toolkit parameters");
        GridBagConstraints c3 = newConstraints();
        int row3 = 0;
        row3 = addRow(toolkit, c3, row3, "Priority:", tip(priorityCombo,
            "Toolkit priority level. 01 unless the profile says otherwise."));
        row3 = addRow(toolkit, c3, row3, "Max timers:", tip(timersCombo,
            "Timers granted to the applet. 00 for an applet installed only to have its MSL "
            + "exercised."));
        row3 = addRow(toolkit, c3, row3, "Menu text length:", tip(menuTextCombo,
            "Maximum text length of a menu entry. 00 when the applet has no menu."));
        row3 = addRow(toolkit, c3, row3, "Max channels:", tip(channelsCombo,
            "BIP channels granted. 00 for a test applet."));

        JPanel raw = group("Raw override and preview");
        GridBagConstraints c4 = newConstraints();
        int row4 = 0;
        row4 = addRow(raw, c4, row4, "Raw parameters:", tip(rawParamsField,
            "Paste a whole install parameters field as hex to bypass the builder entirely. The "
            + "field order this tool builds is its reading of ETSI TS 102 226 clause 8.2.1.3.2, "
            + "and there is no copy of the spec on this machine to check it against - so if your "
            + "provisioning team has a block they trust, this is where it goes. It is still "
            + "checked for being complete TLV before anything is sent."));
        paramsPreview.setEditable(false);
        paramsPreview.setFont(new Font("Monospaced", Font.PLAIN, 11));
        row4 = wide(raw, c4, row4, new JScrollPane(paramsPreview));
        row4 = wide(raw, c4, row4, hint("This is the exact block that will be sent, annotated byte "
            + "by byte with the field each byte was assigned to. Read it against your own copy of "
            + "TS 102 226 before the first install on a card you care about - it is the only "
            + "chance to catch a wrong block, because no command reads install parameters back."));

        return tabOf(new JPanel[] { level, tars, toolkit, raw });
    }

    private JPanel buildOtaTab()
    {
        JPanel target = group("Target");
        GridBagConstraints c = newConstraints();
        int row = 0;
        row = addRow(target, c, row, "Applet TAR:", tip(targetTarCombo,
            "The applet to probe. Status 09 in a response means this TAR does not resolve to an "
            + "installed, selectable application - so no MSL is being applied at all and there is "
            + "nothing to measure."));

        JPanel keys = group("Key set");
        GridBagConstraints c2 = newConstraints();
        int row2 = 0;
        row2 = addRow(keys, c2, row2, "Key version:", tip(otaKvnCombo,
            "The OTA key set version. It goes into the high nibble of both KIc and KID - they "
            + "normally share it, and a mismatch between them is a provisioning error that looks "
            + "exactly like a wrong key."));
        row2 = addRow(keys, c2, row2, "Algorithm:", tip(otaAlgCombo,
            "Sets the low nibble of KIc/KID and the checksum this tool computes. AES uses CMAC, "
            + "the DES family a CBC-MAC."));
        row2 = addRow(keys, c2, row2, "KID key (integrity):", tip(otaKeyField,
            "The KID key, which signs the cryptographic checksum - this is the one MSL probing "
            + "needs. Never stored, never written to a file."));
        row2 = addRow(keys, c2, row2, "KIc key (ciphering):", tip(otaKicKeyField,
            "The KIc key, used only for ciphered probes. Leave blank when KIc equals KID (the "
            + "common case); fill it in when the key set uses different KIc and KID values. "
            + "Never stored, never written to a file."));
        row2 = addRow(keys, c2, row2, "Start counter:", tip(counterField,
            "Hex, and it must be ABOVE the card's stored value. Too low and no response comes back "
            + "at all - which reads exactly like a wrong key. The last response of every run "
            + "prints where the card actually is."));

        JPanel por = group("Proof of Receipt");
        GridBagConstraints c3 = newConstraints();
        int row3 = 0;
        row3 = wide(por, c3, row3, hint("Every answer this tool reads is a PoR, so a run that asks "
            + "for none produces nothing. Both dropdowns are filled from the SDK's own enums, and "
            + "the SPI byte is packed by the SDK's SPI constructor rather than by hand."));
        row3 = addRow(por, c3, row3, "PoR mode:", tip(porModeCombo,
            "POR_REQUIRED for probing. POR_REQUIRED_ON_ERROR would hide exactly the successful "
            + "probes the inference needs."));
        row3 = addRow(por, c3, row3, "PoR delivery:", tip(porSmsCombo,
            "SMS-DELIVER-REPORT or SMS-SUBMIT. There is no default anywhere in the SDK for this - "
            + "it is provisioning knowledge, so it is asked rather than assumed."));
        row3 = wide(por, c3, row3, spiReadout);

        JPanel profileGroup = group("Terminal profile");
        GridBagConstraints c4 = newConstraints();
        int row4 = 0;
        row4 = wide(profileGroup, c4, row4, tip(terminalProfileCheck,
            "A card whose toolkit has never been told what the terminal supports ignores every "
            + "envelope - silently. A plain reader never sends one."));
        row4 = addRow(profileGroup, c4, row4, "Profile bytes:", tip(terminalProfileCombo,
            "On this card family 02 and FFFF both work where FF alone does not."));

        return tabOf(new JPanel[] { target, keys, por, profileGroup });
    }

    private JPanel buildProbeTab()
    {
        JPanel claimed = group("The MSL being verified");
        GridBagConstraints c = newConstraints();
        int row = 0;
        row = wide(claimed, c, row, hint("Only used by verify. Chosen on the same three axes the "
            + "applet was installed with, so what is proved is what was asked for."));
        row = addRow(claimed, c, row, "Integrity:", tip(claimedIntegrityCombo,
            "A packet at exactly this level must not be rejected 0A, and one notch below must be."));
        row = addRow(claimed, c, row, "Ciphering:", claimedCipherCombo);
        row = addRow(claimed, c, row, "Counter:", claimedCounterCombo);
        row = wide(claimed, c, row, claimedReadout);

        JPanel limits = group("What this run may send");
        GridBagConstraints c2 = newConstraints();
        int row2 = 0;
        row2 = addRow(limits, c2, row2, "Probe budget:", tip(budgetCombo,
            "A hard stop. Each probe moves the card's counter and cannot be taken back; discovery "
            + "needs at most 12, verify at most 4."));
        row2 = wide(limits, c2, row2, tip(allowCipheringCheck,
            "Raises the ceiling so ciphering can be measured. Needs a KIc key the card accepts - "
            + "without one every ciphered probe fails for a reason that has nothing to do with "
            + "the MSL."));
        row2 = wide(limits, c2, row2, tip(allowOneHigherCheck,
            "Raises the counter ceiling to PROCESS_IF_ONE_HIGHER. Only useful once the card's own "
            + "counter is known, which the first successful probe reports."));
        row2 = wide(limits, c2, row2, tip(silentDropCheck,
            "For cards that discard a below-MSL packet with no PoR (ENVELOPE 6200) instead of "
            + "answering 0A - a hardening that stops the card being an MSL oracle without the key. "
            + "With this on, once a baseline probe has returned a PoR (proving key, counter, TAR "
            + "and link are good), a later probe that gets no PoR is read as below-MSL. Confirmed "
            + "necessary on the MCI/Hamrah card. Leave off for cards that answer 0A."));
        row2 = wide(limits, c2, row2, hint("The ceiling is this tool's limit, not the card's. "
            + "Discovery holds the two axes it is not measuring at the ceiling, so an axis that "
            + "cannot be reached is reported as unreachable rather than mistaken for a card that "
            + "rejects everything."));

        return tabOf(new JPanel[] { claimed, limits });
    }

    private JPanel buildRunTab()
    {
        JPanel report = group("Report");
        GridBagConstraints rc = newConstraints();
        int rr = 0;
        rr = wide(report, rc, rr, tip(writeReportCheck,
            "Two files per run: an HTML page to read and a CSV row per probe to grep. The live "
            + "log window is gone when the tool closes and the certificate needs the platform to "
            + "open - the report is what a colleague can read next week."));

        JPanel reportRow = new JPanel(new BorderLayout(6, 0));
        reportRow.add(reportFolderField, BorderLayout.CENTER);
        reportRow.add(reportBrowseButton, BorderLayout.EAST);
        reportBrowseButton.addActionListener(new ActionListener()
        {
            public void actionPerformed(ActionEvent event) { browseForReportFolder(); }
        });
        rr = addRow(report, rc, rr, "Report folder:", tip(reportRow,
            "The file is named for the card and the time, so two runs on two cards cannot "
            + "overwrite each other."));
        rr = wide(report, rc, rr, hint("No key material is written to the report - the "
            + "configuration line it carries is the same one that goes on the certificate."));

        JPanel safety = group("Before anything is sent");
        GridBagConstraints c = newConstraints();
        int row = 0;
        row = wide(safety, c, row, hint("Nothing has been sent to the card yet - not a reset, not "
            + "a SELECT. Cancel sends nothing at all."));
        row = wide(safety, c, row, tip(matchCheck,
            "The one acknowledgement every run needs: these values belong to the SIM in the "
            + "reader right now, not the one from the last run."));

        {
            row = wide(safety, c, row, tip(changeCheck,
                "Required by the three jobs that change the card: install, ota-install and "
                + "delete. There is no undo for any of them. An MSL cannot be edited afterwards - "
                + "changing one means deleting the instance and installing again - and a deleted "
                + "applet takes its install parameters with it. Until this is ticked those jobs "
                + "build every packet, print them, and send nothing."));
            row = wide(safety, c, row, hint("The other jobs are read-only in the sense that "
                + "matters: discover, verify and browse install nothing and delete nothing. The "
                + "two probing jobs do move the card's OTA counter, which is why the probe budget "
                + "is a hard stop, and browse over OTA moves it one step per scope."));
        }

        return tabOf(new JPanel[] { report, safety });
    }

    // ==================================================================
    // Behaviour
    // ==================================================================

    private void prefill()
    {
        cardLabelField.setText(profile.get("card.label", ""));
        operatorField.setText(profile.get("operator", ""));

        isdAidCombo.setSelectedItem(profile.get("isd.aid", "A000000151000000"));
        scp02KvnCombo.setSelectedItem(profile.get("scp02.kvn", "01"));
        securityLevelCombo.setSelectedItem(
            UlChoices.securityLevel(profile.get("scp02.securityLevel", "CMAC")));

        capPathField.setText(profile.get("cap.path", ""));
        loadFileAidField.setText(profile.get("loadfile.aid", ""));
        moduleAidField.setText(profile.get("module.aid", ""));
        instanceAidField.setText(profile.get("instance.aid", ""));
        privilegesCombo.setSelectedItem(profile.get("privileges", "00"));

        mslIntegrityCombo.setSelectedItem(IntegrityLevel.CRYPTOGRAPHIC_CHECKSUM);
        mslCipherCombo.setSelectedItem(CipherMode.OFF);
        mslCounterCombo.setSelectedItem(CounterMode.PROCESS_IF_HIGHER);
        tarCombo.setSelectedItem(profile.get("tar", "B00010"));

        targetTarCombo.setSelectedItem(profile.get("target.tar", "B00010"));
        otaKvnCombo.setSelectedItem(profile.get("ota.kvn", "01"));
        otaAlgCombo.setSelectedItem(profile.get("ota.algorithm", "3des2"));
        counterField.setText(profile.get("ota.counter", ""));
        porModeCombo.setSelectedItem(PoRMode.POR_REQUIRED);
        porSmsCombo.setSelectedItem(UlChoices.porSmsType(
            profile.get("ota.porSmsType", "SMS_DELIVER_REPORT")));
        terminalProfileCombo.setSelectedItem(profile.get("terminal.profile", "02"));
        reportFolderField.setText(profile.get("report.folder", ""));

        ramTarCombo.setSelectedItem(profile.get("ram.tar", "000000"));
        blockSizeCombo.setSelectedItem(profile.get("load.blockSize",
                                       String.valueOf(MslCapLoad.DEFAULT_BLOCK_SIZE)));
        deleteAidField.setText(profile.get("delete.aid", ""));

        claimedIntegrityCombo.setSelectedItem(IntegrityLevel.CRYPTOGRAPHIC_CHECKSUM);
        claimedCipherCombo.setSelectedItem(CipherMode.OFF);
        claimedCounterCombo.setSelectedItem(CounterMode.PROCESS_IF_HIGHER);
        budgetCombo.setSelectedItem(profile.get("probe.budget", "24"));
    }

    private void wireValidation()
    {
        DocumentListener listener = new DocumentListener()
        {
            public void insertUpdate(DocumentEvent event)  { revalidateNow(); }
            public void removeUpdate(DocumentEvent event)  { revalidateNow(); }
            public void changedUpdate(DocumentEvent event) { revalidateNow(); }
        };
        ActionListener action = new ActionListener()
        {
            public void actionPerformed(ActionEvent event) { revalidateNow(); }
        };

        JTextField[] fields = { cardLabelField, operatorField, capPathField, reportFolderField,
                                loadFileAidField,
                                moduleAidField, instanceAidField, extraTarsField, rawParamsField,
                                counterField, scp02EncField, scp02MacField, scp02DekField,
                                otaKeyField, otaKicKeyField, deleteAidField };
        for (int i = 0; i < fields.length; i++)
        {
            fields[i].getDocument().addDocumentListener(listener);
        }

        JComboBox[] combos = { modeCombo, isdAidCombo, scp02KvnCombo, securityLevelCombo,
                               privilegesCombo, mslIntegrityCombo, mslCipherCombo, mslCounterCombo,
                               tarCombo, priorityCombo, timersCombo, menuTextCombo, channelsCombo, installFormatCombo,
                               targetTarCombo, otaKvnCombo, otaAlgCombo, porModeCombo, porSmsCombo,
                               terminalProfileCombo, claimedIntegrityCombo, claimedCipherCombo,
                               claimedCounterCombo, budgetCombo,
                               transportCombo, ramTarCombo, blockSizeCombo };
        for (int i = 0; i < combos.length; i++)
        {
            combos[i].addActionListener(action);
            editorOf(combos[i], listener);
        }

        JCheckBox[] boxes = { writeReportCheck, noMslCheck, deleteExistingCheck,
                              makeSelectableCheck, localApduCheck,
                              terminalProfileCheck, allowCipheringCheck, allowOneHigherCheck, silentDropCheck,
                              matchCheck, changeCheck,
                              plainAppletCheck, deleteRelatedCheck, browseApplicationsCheck,
                              browseLoadFilesCheck, browseIsdCheck };
        for (int i = 0; i < boxes.length; i++)
        {
            boxes[i].addActionListener(action);
        }
    }

    private void editorOf(JComboBox combo, DocumentListener listener)
    {
        if (!combo.isEditable()) { return; }

        Component editor = combo.getEditor().getEditorComponent();
        if (editor instanceof JTextField)
        {
            ((JTextField) editor).getDocument().addDocumentListener(listener);
        }
    }

    /**
     * Rebuilds the configuration from the controls, then reports what is still
     * wrong with it. Runs on every keystroke, so the Start button is never
     * enabled for a configuration that would be refused.
     */
    private void revalidateNow()
    {
        List problems;
        try
        {
            harvest();
            problems = config.validate();
        }
        catch (RuntimeException e)
        {
            problems = new ArrayList();
            problems.add(e.getMessage() == null ? e.toString() : e.getMessage());
        }

        updateReadouts();

        if (!matchCheck.isSelected())
        {
            problems.add("Confirm on the Run tab that these values match the SIM in the reader.");
        }
        // install is the one card-changing job with no dry run of its own - it
        // opens a secure channel and sends - so it is gated here. ota-install
        // and delete are not: without the acknowledgement they build every
        // packet, print it and send nothing, which is a run worth being able to
        // start. The checkbox is what turns that dry run into a real one.
        if (installSelected() && !changeCheck.isSelected())
        {
            problems.add("Confirm on the Run tab that this run may install an applet on that SIM.");
        }

        startButton.setEnabled(problems.isEmpty());
        problemsLabel.setText(problems.isEmpty()
            ? "<html><div style='width:" + TEXT_WIDTH + "px'><b>Ready.</b> Nothing has been sent "
              + "yet - Start sends the first byte.</div></html>"
            : bullets(problems));
    }

    private void updateReadouts()
    {
        int mode = selectedMode();
        jobSteps.setText(stepsHtml(stepsFor(mode)));

        // The acknowledgement says what it will actually authorise, which is a
        // different thing per job: for install and delete it is the only thing
        // standing between Start and a change that cannot be undone, and for
        // ota-install it is what turns the dry run into a real load.
        if (mode == MslConfig.MODE_INSTALL)
        {
            changeCheck.setText("I accept that this run installs an applet on that SIM");
        }
        else if (mode == MslConfig.MODE_OTA_INSTALL)
        {
            changeCheck.setText("Really load and install over OTA - leave this clear for a dry "
                                + "run that builds every packet and sends none");
        }
        else if (mode == MslConfig.MODE_DELETE)
        {
            changeCheck.setText("Really delete that AID - leave this clear for a dry run that "
                                + "builds the DELETE and sends it nowhere");
        }
        else
        {
            changeCheck.setText("I accept that this run changes that SIM and cannot be undone "
                                + "(not needed by this job)");
        }

        MslCore.Level level = mslFrom(mslIntegrityCombo, mslCipherCombo, mslCounterCombo);
        mslReadout.setText(noMslCheck.isSelected()
            ? "<html><b>No MSL field</b> - the applet will enforce no minimum.</html>"
            : "<html>Builds MSL byte <b>" + MslCore.hexByte(level.toByte()) + "</b> - "
              + escape(level.describe()) + "</html>");

        MslCore.Level claimed = mslFrom(claimedIntegrityCombo, claimedCipherCombo,
                                        claimedCounterCombo);
        claimedReadout.setText("<html>Verifying MSL <b>" + MslCore.hexByte(claimed.toByte())
                               + "</b> - " + escape(claimed.describe()) + "</html>");

        try
        {
            int spi = UlChoices.spiValue(MslCore.INTEGRITY_CC, MslCore.CIPHER_OFF,
                                         MslCore.COUNTER_HIGHER,
                                         (PoRMode) porModeCombo.getSelectedItem(),
                                         (PoRSMSType) porSmsCombo.getSelectedItem());
            spiReadout.setText("<html>SPI octet 2 will be <b>" + MslCore.hexByte(spi & 0xFF)
                               + "</b>, packed by the SDK's own SPI constructor.</html>");
        }
        catch (RuntimeException e)
        {
            spiReadout.setText("<html><i>SPI could not be built: " + escape(e.getMessage())
                               + "</i></html>");
        }

        updateParamsPreview();
    }

    private void updateParamsPreview()
    {
        try
        {
            byte[] params = config.installParameters();
            StringBuilder text = new StringBuilder();
            text.append(MslCore.hex(params)).append("\n\n");

            List lines = MslCore.describeInstallParameters(params);
            for (int i = 0; i < lines.size(); i++)
            {
                text.append(lines.get(i)).append("\n");
            }
            paramsPreview.setText(text.toString());
            paramsPreview.setCaretPosition(0);
        }
        catch (RuntimeException e)
        {
            paramsPreview.setText("The parameters could not be built:\n" + e.getMessage());
        }
    }

    /** Copies every control into the configuration object. */
    private void harvest()
    {
        config.cardLabel = cardLabelField.getText();
        config.operator = operatorField.getText();

        config.mode = selectedMode();

        {
            config.isdAid = hexOf(isdAidCombo);
            config.scp02Kvn = intOf(scp02KvnCombo, 0x01);
            config.scp02Enc = hexOf(scp02EncField);
            config.scp02Mac = hexOf(scp02MacField);
            config.scp02Dek = hexOf(scp02DekField);
            config.scp02SecurityLevel = String.valueOf(securityLevelCombo.getSelectedItem());

            config.capPath = capPathField.getText().trim();
            config.loadFileAid = hexOf(loadFileAidField);
            config.moduleAid = hexOf(moduleAidField);
            config.instanceAid = hexOf(instanceAidField);
            config.privileges = hexOf(privilegesCombo);
            config.deleteExistingInstance = deleteExistingCheck.isSelected();
            config.makeSelectable = makeSelectableCheck.isSelected();
            config.buildInstallApduLocally = localApduCheck.isSelected();

            config.msl = noMslCheck.isSelected()
                ? null
                : mslFrom(mslIntegrityCombo, mslCipherCombo, mslCounterCombo);

            config.tars.clear();
            addTar(String.valueOf(tarCombo.getSelectedItem()));
            String[] extra = extraTarsField.getText().split(",");
            for (int i = 0; i < extra.length; i++)
            {
                addTar(extra[i]);
            }

            config.priority = intOf(priorityCombo, 0x01);
            config.maxTimers = intOf(timersCombo, 0x00);
            config.maxMenuTextLength = intOf(menuTextCombo, 0x00);
            config.maxChannels = intOf(channelsCombo, 0x00);
            config.installFormat = installFormatCombo.getSelectedIndex() == 1
                ? MslCore.FORMAT_SIM : MslCore.FORMAT_UICC;

            String raw = rawParamsField.getText().trim();
            config.rawInstallParameters = raw.length() == 0 ? null : MslCore.unhex(raw);
        }
        {
            config.transport = transportCombo.getSelectedIndex() == 1
                ? MslConfig.TRANSPORT_ISD : MslConfig.TRANSPORT_OTA;
            config.ramTar = hexOf(ramTarCombo);
            config.loadBlockSize = decimalOf(blockSizeCombo, MslCapLoad.DEFAULT_BLOCK_SIZE);
            config.plainApplet = plainAppletCheck.isSelected();

            config.browseApplications = browseApplicationsCheck.isSelected();
            config.browseLoadFiles = browseLoadFilesCheck.isSelected();
            config.browseIssuerSecurityDomain = browseIsdCheck.isSelected();

            config.deleteAid = hexOf(deleteAidField);
            config.deleteRelatedObjects = deleteRelatedCheck.isSelected();

            // The one acknowledgement that authorises an irreversible send. The
            // scripts read this, not the checkbox: a dialog that was cancelled
            // never produced a config at all.
            config.confirmIrreversible = changeCheck.isSelected();
        }
        {
            config.targetTar = hexOf(targetTarCombo);
            config.otaKvn = intOf(otaKvnCombo, 0x01);
            config.otaAlgorithm = String.valueOf(otaAlgCombo.getSelectedItem());
            config.otaKey = hexOf(otaKeyField);
            config.otaKicKey = hexOf(otaKicKeyField);
            config.startCounter = longOf(counterField);

            PoRMode porMode = (PoRMode) porModeCombo.getSelectedItem();
            PoRSMSType porSms = (PoRSMSType) porSmsCombo.getSelectedItem();
            config.porMode = porMode.name();
            config.porSmsType = porSms.name();
            // Packed by the SDK, not here: the same constructor the probe script
            // uses to build the SPI it actually sends.
            config.spiSecondOctet = UlChoices.spiValue(
                MslCore.INTEGRITY_CC, MslCore.CIPHER_OFF, MslCore.COUNTER_HIGHER,
                porMode, porSms) & 0xFF;

            config.writeReport = writeReportCheck.isSelected();
            config.reportFolder = reportFolderField.getText().trim();

            config.sendTerminalProfile = terminalProfileCheck.isSelected();
            config.terminalProfile = hexOf(terminalProfileCombo);

            config.claimedMsl = config.mode == MslConfig.MODE_VERIFY
                ? mslFrom(claimedIntegrityCombo, claimedCipherCombo, claimedCounterCombo)
                : null;
            config.probeBudget = intOf(budgetCombo, 24);
            config.allowCiphering = allowCipheringCheck.isSelected();
            config.allowOneHigher = allowOneHigherCheck.isSelected();
            config.silentDrop = silentDropCheck.isSelected();
        }
    }

    private void addTar(String text)
    {
        text = text == null ? "" : text.trim();
        if (text.length() == 0) { return; }

        config.tars.add(MslCore.unhex(text));
    }

    private MslCore.Level mslFrom(JComboBox integrity, JComboBox cipher, JComboBox counter)
    {
        return new MslCore.Level(
            UlChoices.integrityValue((IntegrityLevel) integrity.getSelectedItem()),
            UlChoices.cipherValue((CipherMode) cipher.getSelectedItem()),
            UlChoices.counterValue((CounterMode) counter.getSelectedItem()));
    }

    /** The job chosen on the Job tab. */
    private int selectedMode()
    {
        int index = modeCombo.getSelectedIndex();
        if (index == 1) { return MslConfig.MODE_VERIFY; }
        if (index == 2) { return MslConfig.MODE_INSTALL; }
        if (index == 3) { return MslConfig.MODE_OTA_INSTALL; }
        if (index == 4) { return MslConfig.MODE_BROWSE; }
        if (index == 5) { return MslConfig.MODE_DELETE; }
        return MslConfig.MODE_DISCOVER;
    }

    private boolean installSelected()
    {
        return selectedMode() == MslConfig.MODE_INSTALL;
    }

    /** The steps the selected job will take, in order, for the Job tab. */
    private String[] stepsFor(int mode)
    {
        if (mode == MslConfig.MODE_INSTALL)
        {
            return new String[] {
                "Open an SCP02 secure channel to the ISD.",
                "Optionally DELETE an existing instance with the same AID.",
                "Load the CAP if the executable load file is not already on the card.",
                "INSTALL [for install and make selectable] with the parameters built on the MSL tab.",
                "Confirm in the registry that the instance is SELECTABLE - an applet that is not "
                + "selectable is unreachable by its TAR, and OTA answers 09 rather than anything "
                + "about security." };
        }
        if (mode == MslConfig.MODE_OTA_INSTALL)
        {
            return new String[] {
                "Read the CAP and build INSTALL [for load], the LOAD chain and INSTALL [for "
                + "install] - then print every one of them.",
                "Cross-check the load file against the SDK's own reading of the same CAP: same "
                + "AID, same SHA-1, or nothing is sent.",
                "Stop there unless the irreversible-change box is ticked. That is the dry run.",
                "Send TERMINAL PROFILE, then each APDU inside its own secured packet to the card "
                + "manager TAR, checking both the PoR status and the card's own status word for "
                + "each.",
                "Read the registry back over OTA to confirm the instance is there." };
        }
        if (mode == MslConfig.MODE_BROWSE)
        {
            return new String[] {
                "Open the chosen road: a secured packet to the card manager, or an SCP02 channel.",
                "GET STATUS once per scope selected on the Card content tab.",
                "Follow the card's 6310 continuations until the listing is complete.",
                "Print every AID with its life cycle, and the modules inside each package. "
                + "Nothing is written to the card." };
        }
        if (mode == MslConfig.MODE_DELETE)
        {
            return new String[] {
                "Build the DELETE and print it.",
                "Read the registry first and say what is actually at that AID - refusing to send "
                + "when the card does not have it.",
                "Stop there unless the irreversible-change box is ticked. That is the dry run.",
                "Send the DELETE and report both the PoR status and the card's own status word." };
        }
        return new String[] {
            "Send TERMINAL PROFILE so the card's toolkit is awake.",
            "Send one secured packet per probe, each carrying a single inert byte.",
            "Read the response status: 0A means below the MSL, anything else means the packet "
            + "got past the security gate.",
            "Infer the MSL, then check the inference with further probes." };
    }

    private void onStart()
    {
        harvest();
        if (!config.validate().isEmpty()) { return; }

        finish(true);
    }

    private void browseForReportFolder()
    {
        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Where should the report be written?");
        chooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);

        String current = reportFolderField.getText().trim();
        if (current.length() > 0)
        {
            java.io.File start = new java.io.File(current);
            if (start.isDirectory()) { chooser.setCurrentDirectory(start); }
        }

        if (chooser.showOpenDialog(this) == JFileChooser.APPROVE_OPTION)
        {
            reportFolderField.setText(chooser.getSelectedFile().getAbsolutePath());
        }
    }

    private void browseForCap()
    {
        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Select the CAP file");
        if (chooser.showOpenDialog(this) == JFileChooser.APPROVE_OPTION)
        {
            capPathField.setText(chooser.getSelectedFile().getAbsolutePath());
        }
    }

    // ==================================================================
    // Small helpers, same shapes as the lifecycle dialog
    // ==================================================================

    private static JComboBox editable(String[] values)
    {
        JComboBox combo = new JComboBox(values);
        combo.setEditable(true);
        return combo;
    }

    /**
     * Gives every input the same width and height.
     *
     * Swing sizes a text field from its column count and a combo from its widest
     * entry, so a form built without this ends up with boxes of six different
     * lengths down one column - which is most of what made the first version
     * look unfinished.
     */
    private static Component sized(Component component)
    {
        Dimension preferred = component.getPreferredSize();
        int height = Math.max(preferred.height, 24);
        component.setPreferredSize(new Dimension(FIELD_WIDTH, height));
        component.setMinimumSize(new Dimension(160, height));
        return component;
    }

    private JPanel group(String title)
    {
        JPanel panel = new JPanel(new GridBagLayout());
        panel.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createTitledBorder(
                BorderFactory.createLineBorder(new Color(200, 210, 225)), title,
                javax.swing.border.TitledBorder.LEFT, javax.swing.border.TitledBorder.TOP,
                null, new Color(35, 60, 100)),
            BorderFactory.createEmptyBorder(4, 8, 8, 8)));
        return panel;
    }

    /** Stacks the groups down the tab, each taking only the height it needs. */
    private JPanel tabOf(JPanel[] groups)
    {
        JPanel outer = new JPanel(new GridBagLayout());
        GridBagConstraints c = new GridBagConstraints();
        c.gridx = 0;
        c.weightx = 1;
        c.fill = GridBagConstraints.HORIZONTAL;
        c.insets = new Insets(6, 8, 2, 8);
        c.anchor = GridBagConstraints.NORTHWEST;

        for (int i = 0; i < groups.length; i++)
        {
            c.gridy = i;
            outer.add(groups[i], c);
        }
        c.gridy = groups.length;
        c.weighty = 1;
        c.fill = GridBagConstraints.BOTH;
        outer.add(Box.createGlue(), c);
        return outer;
    }

    /**
     * Every tab is wrapped, not just the long ones: a tab that overflows without
     * a scroll pane hides its lower controls with no way to reach them.
     */
    private JComponent inScroller(JPanel form)
    {
        JScrollPane scroller = new JScrollPane(form);
        scroller.setBorder(BorderFactory.createEmptyBorder());
        scroller.getVerticalScrollBar().setUnitIncrement(16);
        return scroller;
    }

    private GridBagConstraints newConstraints()
    {
        GridBagConstraints c = new GridBagConstraints();
        c.insets = new Insets(4, 6, 4, 6);
        c.anchor = GridBagConstraints.WEST;
        return c;
    }

    private int addRow(JPanel panel, GridBagConstraints c, int row, String label, Component field)
    {
        c.gridx = 0;
        c.gridy = row;
        c.weightx = 0;
        c.fill = GridBagConstraints.NONE;
        c.anchor = GridBagConstraints.EAST;

        JLabel caption = new JLabel(label);
        caption.setPreferredSize(new Dimension(128, caption.getPreferredSize().height));
        panel.add(caption, c);

        c.gridx = 1;
        c.weightx = 1;
        c.fill = GridBagConstraints.HORIZONTAL;
        c.anchor = GridBagConstraints.WEST;
        panel.add(sized(field), c);
        return row + 1;
    }

    private int wide(JPanel panel, GridBagConstraints c, int row, Component component)
    {
        c.gridx = 0;
        c.gridy = row;
        c.gridwidth = 2;
        c.weightx = 1;
        c.fill = GridBagConstraints.HORIZONTAL;
        panel.add(component, c);
        c.gridwidth = 1;
        return row + 1;
    }

    /**
     * Attaches the long explanation to the control it is about, instead of
     * printing it beside it. Nothing is lost - the reasoning is one hover away,
     * attached to the thing it describes.
     */
    private JComponent tip(JComponent component, String text)
    {
        component.setToolTipText("<html><div style='width:340px'>" + escape(text) + "</div></html>");
        return component;
    }

    private JLabel hint(String text)
    {
        JLabel label = new JLabel("<html><div style='width:" + TEXT_WIDTH + "px'>"
                                  + escape(text) + "</div></html>");
        label.setForeground(new Color(80, 90, 100));
        label.setBorder(BorderFactory.createEmptyBorder(1, 2, 5, 2));
        return label;
    }

    /** A numbered list, for describing a sequence the operator is about to start. */
    private String stepsHtml(String[] items)
    {
        StringBuilder html = new StringBuilder("<html><div style='width:" + TEXT_WIDTH
                                               + "px'><ol>");
        for (int i = 0; i < items.length; i++)
        {
            html.append("<li style='margin-bottom:4px'>").append(escape(items[i])).append("</li>");
        }
        html.append("</ol></div></html>");
        return html.toString();
    }

    private String bullets(List problems)
    {
        StringBuilder html = new StringBuilder("<html><div style='width:" + TEXT_WIDTH + "px'>");
        html.append("<b>Not ready - nothing will be sent:</b><ul>");
        for (int i = 0; i < problems.size(); i++)
        {
            html.append("<li>").append(escape(String.valueOf(problems.get(i)))).append("</li>");
        }
        html.append("</ul></div></html>");
        return html.toString();
    }

    private static String escape(String text)
    {
        if (text == null) { return ""; }

        StringBuilder out = new StringBuilder();
        for (int i = 0; i < text.length(); i++)
        {
            char ch = text.charAt(i);
            if (ch == '<')      { out.append("&lt;"); }
            else if (ch == '>') { out.append("&gt;"); }
            else if (ch == '&') { out.append("&amp;"); }
            else                { out.append(ch); }
        }
        return out.toString();
    }

    // -- reading controls ------------------------------------------------

    private byte[] hexOf(JTextField field)
    {
        String text = new String(field instanceof JPasswordField
            ? ((JPasswordField) field).getPassword() : field.getText().toCharArray()).trim();
        return text.length() == 0 ? new byte[0] : MslCore.unhex(text);
    }

    private byte[] hexOf(JComboBox combo)
    {
        Object value = combo.getSelectedItem();
        String text = value == null ? "" : String.valueOf(value).trim();
        return text.length() == 0 ? new byte[0] : MslCore.unhex(text);
    }

    private int intOf(JComboBox combo, int fallback)
    {
        Object value = combo.getSelectedItem();
        String text = value == null ? "" : String.valueOf(value).trim();
        if (text.length() == 0) { return fallback; }

        try
        {
            return Integer.parseInt(text, 16);
        }
        catch (NumberFormatException e)
        {
            return fallback;
        }
    }

    /**
     * A decimal value from an editable combo.
     *
     * Decimal, not hex, and the only such field in this dialog: a LOAD block
     * size is a byte count an operator thinks about in tens, not a card value.
     * Everything else here is hex because the card's own documents are.
     */
    private int decimalOf(JComboBox combo, int fallback)
    {
        Object value = combo.getSelectedItem();
        String text = value == null ? "" : String.valueOf(value).trim();
        if (text.length() == 0) { return fallback; }

        try
        {
            return Integer.parseInt(text, 10);
        }
        catch (NumberFormatException e)
        {
            return fallback;
        }
    }

    private long longOf(JTextField field)
    {
        String text = field.getText().trim();
        if (text.length() == 0) { return 0; }

        try
        {
            return Long.parseLong(text, 16);
        }
        catch (NumberFormatException e)
        {
            return 0;
        }
    }
}

// --------------------------------------------------------------------------
// scripts/MslScript.java
// --------------------------------------------------------------------------

/**
 * All three MSL jobs, in one script.
 *
 * The MSL is not a command and not a card setting: it is a field inside the
 * INSTALL [for install and make selectable] parameters, fixed for the lifetime
 * of that applet instance. Changing an applet's MSL means deleting the instance
 * and installing it again - which is why this script offers to delete first,
 * and why the parameters block is shown for review before anything is sent.
 *
 * Governing specs: GlobalPlatform Card Specification 2.2 clause 11.5 for
 * INSTALL, ETSI TS 102 226 clause 8.2.1.3.2 for the toolkit application
 * specific parameters the MSL lives in.
 *
 * Why one script rather than two, which is what this was:
 *
 * Card content management is GlobalPlatform work and wants SCP02Script; OTA
 * probing goes through SMS-PP envelopes, and the SDK's ready-made procedure for
 * those lives on the other script tree. The two base classes cannot be combined,
 * so something had to give - and what gave is the envelope, not the secure
 * channel. INSTALL keeps the SDK's proven SCP02 implementation, and the probing
 * half frames its own ENVELOPE around a packet the SDK still builds
 * (SecuredCommandPacketFactory) and a response this tool parses with code the
 * self-test covers byte for byte (MslCore.buildEnvelope / parsePor, ported from
 * the Python tool already proven against these cards).
 *
 * That is the right way round for the risk: a mistake in the install half
 * changes a card, while a mistake in the envelope half produces no PoR and an
 * INCONCLUSIVE probe, which the inference already refuses to draw a conclusion
 * from.
 *
 * Nothing is sent until the run dialog is confirmed. Cancel sends nothing at
 * all, not even a reset.
 */
public class MslScript extends SCP02Script
{
    private MslConfig cfg;
    private MslLog out;
    private MslReport report;

    private String jobName()
    {
        if (cfg.mode == MslConfig.MODE_INSTALL)     { return "install"; }
        if (cfg.mode == MslConfig.MODE_OTA_INSTALL) { return "ota-install"; }
        if (cfg.mode == MslConfig.MODE_BROWSE)      { return "browse"; }
        if (cfg.mode == MslConfig.MODE_DELETE)      { return "delete"; }
        if (cfg.mode == MslConfig.MODE_VERIFY)      { return "verify"; }
        return "discover";
    }

    protected void run()
    {
        Frame parent = parentFrame();
        PrintWriter output = scriptOutput();

        cfg = MslConfigDialog.prompt(parent, "MslScript");

        if (cfg == null)
        {
            if (output != null)
            {
                output.println("MSL checking: configuration cancelled. Nothing was sent to the card.");
                output.flush();
            }
            return;
        }

        out = new MslLog("MSL checking - " + jobName() + " - " + cfg.cardLabel, output);

        try
        {
            getCertificate().storeAdditionalInformation("Script", "MslScript (" + jobName() + ")");
            getCertificate().storeAdditionalInformation("Run configuration",
                                                        cfg.describeForCertificate());
        }
        catch (RuntimeException e)
        {
            out.warn("Could not write to the certificate: " + e.getMessage());
        }

        report = new MslReport(cfg, jobName());

        try
        {
            if (cfg.mode == MslConfig.MODE_INSTALL)          { install(); }
            else if (cfg.mode == MslConfig.MODE_OTA_INSTALL) { otaInstall(); }
            else if (cfg.mode == MslConfig.MODE_BROWSE)      { browse(); }
            else if (cfg.mode == MslConfig.MODE_DELETE)      { deleteObject(); }
            else                                             { probe(); }
        }
        catch (MslProbing.BudgetExhausted stop)
        {
            out.warn("Stopped: " + stop.getMessage() + ". Raise the probe budget on the dialog if "
                     + "the walk was genuinely unfinished - but read the log first, because a "
                     + "budget hit usually means the probes were not being answered.");
        }
        catch (Throwable t)
        {
            out.error("Unhandled " + t.getClass().getName() + ": " + t.getMessage());
        }
        finally
        {
            writeReport();
            out.markFinished();
        }
    }

    // ------------------------------------------------------------------

    private void install()
    {
        byte[] parameters = cfg.installParameters();

        out.heading("What will be installed");
        out.info("instance AID      : " + MslCore.hex(cfg.instanceAid));
        out.info("module AID        : " + MslCore.hex(cfg.moduleAid));
        out.info("load file AID     : " + MslCore.hex(cfg.loadFileAid));
        out.info("privileges        : " + MslCore.hex(cfg.privileges));
        out.info("install parameters: " + MslCore.hex(parameters));
        out.lines(MslCore.describeInstallParameters(parameters));

        report.installLine(MslCore.hex(parameters));
        report.installLine("");
        List dump = MslCore.describeInstallParameters(parameters);
        for (int i = 0; i < dump.size(); i++)
        {
            report.installLine(String.valueOf(dump.get(i)));
        }

        // Say the MSL back from the bytes rather than from the dialog field. If
        // the builder and the parser ever disagree, this line is where it shows,
        // before the card is touched rather than after.
        MslCore.Level readBack = null;
        try
        {
            readBack = MslCore.mslOfInstallParameters(parameters);
        }
        catch (RuntimeException e)
        {
            out.error("The install parameters do not parse back: " + e.getMessage());
            out.error("Refusing to send a parameters block this tool cannot read. Fix the values, "
                      + "or paste a raw field you have verified yourself.");
            return;
        }
        out.info("MSL encoded in those bytes: "
                 + (readBack == null ? "none - this applet will enforce no minimum"
                                     : readBack.describe()));

        out.heading("Opening a secure channel");
        if (!openSession()) { return; }

        if (cfg.deleteExistingInstance)
        {
            deleteInstance();
        }

        if (!ensureLoadFilePresent()) { return; }

        out.heading("INSTALL [for install" + (cfg.makeSelectable ? " and make selectable" : "")
                    + "]");
        int status = cfg.buildInstallApduLocally
            ? installWithLocalApdu(parameters)
            : installWithSdkCommand(parameters);

        if (status != 0x9000)
        {
            out.error("INSTALL returned " + word(status) + " - the applet was not installed.");
            explainInstallFailure(status);
            record(MslReport.FAIL, "INSTALL returned " + word(status),
                   "Nothing was installed. The parameter dump above is what was sent.");
            return;
        }
        out.good("INSTALL returned 9000");

        confirmRegistry();

        out.heading("What is proven, and what is not");
        out.info("A 9000 from INSTALL means the card accepted the parameters block. It does NOT "
                 + "mean the MSL inside it is being enforced the way it reads: nothing on a card "
                 + "reads install parameters back, so the only proof is behavioural.");
        record(MslReport.PASS, "installed with MSL "
               + (readBack == null ? "none" : MslCore.hexByte(readBack.toByte())),
               "9000 means the card accepted the parameters block. It does NOT mean the MSL is "
               + "enforced as it reads - nothing reads install parameters back, so run the verify "
               + "job to close that gap.");

        out.info("Run this script again with the verify job against TAR "
                 + (cfg.tars.isEmpty() ? "<the TAR you installed>"
                                       : MslCore.hex((byte[]) cfg.tars.get(0)))
                 + ", claimed MSL "
                 + (readBack == null ? "<none>" : MslCore.hexByte(readBack.toByte()))
                 + ", to close that gap.");
    }

    // ------------------------------------------------------------------
    // The two ways to send INSTALL
    // ------------------------------------------------------------------

    /**
     * The SDK's typed command - InstallForInstallAndMakeSelectableCommand when
     * the applet is to be made selectable, InstallForInstallCommand when it is
     * not. Both expose the same fluent setters (confirmed from the 3.8.0
     * Javadoc, not inferred from the names).
     *
     * parameters(byte[]) is documented, in full, as "the install parameters" -
     * the Javadoc's method detail adds nothing beyond that, which was checked
     * directly rather than assumed. So the whole field is passed on the reading
     * that "the install parameters" means exactly the field GlobalPlatform
     * calls by that name: C9 first, then EA/CA. If the SDK instead wraps what
     * it is given, this call produces a doubly-wrapped C9 and the card answers
     * 6A80 - the dialog's "build the INSTALL APDU here" switch is the way to
     * test that alternative without guessing. Whichever route runs, the bytes
     * actually sent are printed above.
     */
    private int installWithSdkCommand(byte[] parameters)
    {
        if (cfg.makeSelectable)
        {
            out.step("built by InstallForInstallAndMakeSelectableCommand");

            InstallForInstallAndMakeSelectableCommand install =
                new InstallForInstallAndMakeSelectableCommand();

            install.executableLoadFileAID(cfg.loadFileAid)
                   .executableModuleAID(cfg.moduleAid)
                   .applicationAID(cfg.instanceAid)
                   .privileges(cfg.privileges)
                   .parameters(parameters);

            return sendSecure(install).getStatusWord();
        }

        out.step("built by InstallForInstallCommand ([for install], not made selectable)");

        InstallForInstallCommand install = new InstallForInstallCommand();

        install.executableLoadFileAID(cfg.loadFileAid)
               .executableModuleAID(cfg.moduleAid)
               .applicationAID(cfg.instanceAid)
               .privileges(cfg.privileges)
               .parameters(parameters);

        return sendSecure(install).getStatusWord();
    }

    /**
     * The same command, built here byte for byte and sent through the same
     * secure channel.
     *
     * Kept as an alternative route for the one question the Javadoc does not
     * answer: whether parameters(byte[]) takes the whole install parameters
     * field or only the application-specific part. Here every byte from CLA to
     * the last install-token byte is this tool's own, so a 6A80 from the SDK
     * path that goes away on this one localises the disagreement precisely.
     */
    private int installWithLocalApdu(byte[] parameters)
    {
        byte[] apdu = MslCore.buildInstallApdu(cfg.loadFileAid, cfg.moduleAid, cfg.instanceAid,
                                               cfg.privileges, parameters, cfg.makeSelectable);
        out.step("built here: " + MslCore.hex(apdu));

        GenericISOCommand command = new GenericISOCommand("INSTALL");
        command.cla(apdu[0] & 0xFF)
               .ins(apdu[1] & 0xFF)
               .p1(apdu[2] & 0xFF)
               .p2(apdu[3] & 0xFF);

        byte[] data = new byte[apdu.length - 5];
        System.arraycopy(apdu, 5, data, 0, data.length);
        command.data(data).noLe();

        return sendSecure(command).getStatusWord();
    }

    private void explainInstallFailure(int status)
    {
        if (status == 0x6A80)
        {
            out.info("6A80 is 'incorrect parameters in the data field' - the card did not accept "
                     + "the install parameters block. Most likely causes, in order: the toolkit "
                     + "field order does not match this card's reading of TS 102 226; the SDK "
                     + "wrapped the parameters differently than expected (retry with the dialog's "
                     + "'build the INSTALL APDU here' box ticked); a TAR that is already taken.");
        }
        else if (status == 0x6985)
        {
            out.info("6985 usually means an instance with this AID already exists. Tick the "
                     + "delete box, or choose another instance AID.");
        }
        else if (status == 0x6A88)
        {
            out.info("6A88 means the load file or module AID is not on the card. Check the two "
                     + "AIDs against the registry listing above, or give a CAP path so the "
                     + "package is loaded first.");
        }
        else if (status == 0x6982)
        {
            out.info("6982 means the secure channel is not in the state the card expects - the "
                     + "session may have been aborted by an earlier failed command. Re-run.");
        }
    }

    // ------------------------------------------------------------------
    // Session, registry, load file
    // ------------------------------------------------------------------

    private boolean openSession()
    {
        reset();

        ISOResponse selected = send(new SelectCommand().aid(cfg.isdAid));
        if (selected.getStatusWord() != 0x9000)
        {
            out.error("SELECT of the ISD " + MslCore.hex(cfg.isdAid) + " returned "
                      + word(selected.getStatusWord())
                      + " - check the AID, or run DiscoverSecurityDomainsScript to read the real "
                      + "one out of the card's own registry.");
            return false;
        }

        ISOResponse opened = openSecureChannel(
            new SCP02KeyVersion(cfg.scp02Kvn, cfg.scp02Enc, cfg.scp02Mac, cfg.scp02Dek),
            securityLevel());

        if (opened.getStatusWord() != 0x9000)
        {
            out.error("The secure channel failed: " + word(opened.getStatusWord())
                      + " - wrong key version or wrong keys. GET DATA tag E0 lists what the card "
                      + "actually has.");
            return false;
        }

        out.good("SCP02 open at " + securityLevel() + " with key version "
                 + MslCore.hexByte(cfg.scp02Kvn));
        return true;
    }

    private SecurityLevel securityLevel()
    {
        if ("CDECRYPTION_CMAC".equalsIgnoreCase(cfg.scp02SecurityLevel))
        {
            return SecurityLevel.CDECRYPTION_CMAC;
        }
        if ("NO_SECURE_MESSAGING".equalsIgnoreCase(cfg.scp02SecurityLevel))
        {
            return SecurityLevel.NO_SECURE_MESSAGING;
        }
        return SecurityLevel.CMAC;
    }

    private void deleteInstance()
    {
        out.heading("Removing any existing instance");

        DeleteCommand delete = new DeleteCommand().aid(cfg.instanceAid);
        int status = sendSecure(delete).getStatusWord();

        if (status == 0x9000)
        {
            out.good("deleted " + MslCore.hex(cfg.instanceAid));
        }
        else if (status == 0x6A88 || status == 0x6A82)
        {
            out.info("nothing to delete - no instance with that AID");
        }
        else
        {
            out.warn("DELETE returned " + word(status) + "; carrying on, but INSTALL will fail "
                     + "with 6985 if the instance is still there");
        }
    }

    /**
     * Loads the CAP if the load file is missing and a path was given.
     *
     * An install cannot invent a package. When the load file is absent and no
     * CAP was named, this stops with the reason rather than sending an INSTALL
     * that can only answer 6A88.
     */
    private boolean ensureLoadFilePresent()
    {
        if (findInRegistry(GetStatusCommand.StatusType.EXECUTABLE_LOAD_FILES_AND_EXECUTABLE_MODULES,
                           cfg.loadFileAid) != null)
        {
            out.info("load file " + MslCore.hex(cfg.loadFileAid) + " is already on the card");
            return true;
        }

        if (cfg.capPath == null || cfg.capPath.trim().length() == 0)
        {
            out.error("The load file " + MslCore.hex(cfg.loadFileAid) + " is not on the card and "
                      + "no CAP path was given. Load the package first, or name the CAP on the "
                      + "applet tab.");
            return false;
        }

        File cap = new File(cfg.capPath);
        if (!cap.isFile())
        {
            out.error("No CAP file at " + cap.getAbsolutePath());
            return false;
        }

        out.heading("Loading " + cap.getName());
        LoadSequence sequence;
        try
        {
            sequence = new LoadSequence(cfg.capPath);
        }
        catch (Exception e)
        {
            out.error("Could not read the CAP: " + e.getMessage());
            return false;
        }

        InstallForLoadCommand forLoad = new InstallForLoadCommand();
        forLoad.loadFileAID(sequence.getLoadFileAID());
        forLoad.loadFileDataBlockHash(sequence.getLoadFileDataBlockHash());

        int status = sendSecure(forLoad).getStatusWord();
        if (status != 0x9000)
        {
            out.error("INSTALL [for load] returned " + word(status));
            return false;
        }

        status = runSecureCommandSequence(sequence).getStatusWord();
        if (status != 0x9000)
        {
            out.error("the LOAD chain returned " + word(status));
            return false;
        }

        out.good("loaded " + MslCore.hex(sequence.getLoadFileAID()));
        return true;
    }

    private void confirmRegistry()
    {
        out.heading("Registry check");

        RegistryData entry = findInRegistry(
            GetStatusCommand.StatusType.APPLICATIONS_INCLUDING_SECURITY_DOMAINS, cfg.instanceAid);

        if (entry == null)
        {
            out.error("INSTALL answered 9000 but " + MslCore.hex(cfg.instanceAid)
                      + " is not in the registry. Treat the install as failed.");
            return;
        }

        int lifeCycle = entry.hasLifeCycleState() ? (entry.getLifeCycleState()[0] & 0xFF) : -1;
        String name;
        try
        {
            name = ApplicationLifeCycleState.fromValue(lifeCycle).getName();
        }
        catch (RuntimeException e)
        {
            name = "application-specific";
        }
        out.good(MslCore.hex(cfg.instanceAid) + " is installed, life cycle " + name + " ("
                 + MslCore.hexByte(lifeCycle) + ")");

        if (lifeCycle == 0x03)
        {
            out.warn("INSTALLED but not SELECTABLE: the applet will not answer a SELECT by AID "
                     + "and is not reachable by its TAR either - OTA answers 09 (TAR unknown). "
                     + "Nothing about its MSL can be tested in this state.");
        }
    }

    private RegistryData findInRegistry(GetStatusCommand.StatusType type, byte[] aid)
    {
        GetStatusCommand command = new GetStatusCommand();
        command.statusType(type);
        command.deprecatedResponseFormat();

        GetStatusSequence sequence = new GetStatusSequence(command);
        ISOResponse response = runSecureCommandSequence(sequence);
        int status = response.getStatusWord();

        if (status != 0x9000 && status != 0x6310)
        {
            if (status != 0x6A88)
            {
                out.warn("GET STATUS (" + type + ") returned " + word(status));
            }
            return null;
        }

        GetStatusResponse parsed =
            new GetStatusResponse(command, sequence.getCompleteResponseData());
        List entries = parsed.getAllRegistryData();

        for (int i = 0; i < entries.size(); i++)
        {
            RegistryData entry = (RegistryData) entries.get(i);
            if (entry.hasAID() && MslCore.equal(entry.getAID(), aid)) { return entry; }
        }
        return null;
    }

    private static String word(int status)
    {
        return MslCore.hexByte(status >> 8) + MslCore.hexByte(status);
    }

    // ==================================================================
    // ota-install - load a CAP and install from it, all over OTA
    // ==================================================================

    /**
     * Card content management over Remote Application Management: INSTALL [for
     * load], the LOAD chain and INSTALL [for install] each wrapped in its own
     * SCP80 secured packet addressed to the card manager's TAR.
     *
     * This is the Java side of what tools/msl_tool.py does with `ota-install`,
     * and it is deliberately the same shape: build everything, print everything,
     * send nothing unless the operator has ticked the irreversible box.
     *
     * The serialization question - whether the load file this tool builds is the
     * load file the card should get - is not answered by trusting MslCapLoad. It
     * is answered by asking the SDK's own LoadSequence for the same CAP's load
     * file AID and SHA-1, and refusing to send if either disagrees. A matching
     * hash over the whole load file means the concatenation is byte-identical to
     * the SDK's, which is the one thing that has to be exactly right here.
     */
    private void otaInstall()
    {
        File cap = new File(cfg.capPath.trim());

        out.heading("Reading " + cap.getName());
        MslCapLoad.Sequence sequence;
        try
        {
            sequence = MslCapLoad.read(cap, cfg.loadBlockSize);
        }
        catch (IOException e)
        {
            out.error("Could not read the CAP: " + e.getMessage());
            record(MslReport.FAIL, "the CAP could not be read", e.getMessage());
            return;
        }
        catch (RuntimeException e)
        {
            out.error("The CAP does not read as a Java Card archive: " + e.getMessage());
            record(MslReport.FAIL, "the CAP does not parse", e.getMessage());
            return;
        }

        out.info("load file (ELF) AID : " + MslCore.hex(sequence.elfAid));
        for (int i = 0; i < sequence.appletAids.size(); i++)
        {
            out.info("applet AID declared : "
                     + MslCore.hex((byte[]) sequence.appletAids.get(i)));
        }
        out.info("load file size      : " + sequence.loadFile.length + " bytes");
        out.info("load file SHA-1     : " + MslCore.hex(sequence.loadFileHash));
        out.info("LOAD blocks         : " + (sequence.apdus.size() - 1) + " of up to "
                 + cfg.loadBlockSize + " bytes");

        boolean sdkAgrees = sdkConfirmsLoadFile(sequence);

        // The install parameters, said back from the bytes rather than from the
        // dialog - the same read-back the contact install does, for the same
        // reason: nothing on the card reads them afterwards.
        byte[] parameters = cfg.installParameters();
        out.heading("What will be installed");
        out.info("module AID        : " + MslCore.hex(cfg.moduleAid));
        out.info("instance AID      : " + MslCore.hex(cfg.instanceAid));
        out.info("privileges        : " + MslCore.hex(cfg.privileges));
        out.info("install parameters: " + MslCore.hex(parameters));
        out.lines(MslCore.describeInstallParameters(parameters));

        MslCore.Level readBack;
        try
        {
            readBack = MslCore.mslOfInstallParameters(parameters);
        }
        catch (RuntimeException e)
        {
            out.error("The install parameters do not parse back: " + e.getMessage());
            record(MslReport.FAIL, "the install parameters do not parse back", e.getMessage());
            return;
        }
        out.info("MSL encoded in those bytes: "
                 + (readBack == null ? "none - this applet will enforce no minimum"
                                     : readBack.describe()));

        byte[] installApdu = MslCore.buildInstallApdu(sequence.elfAid, cfg.moduleAid,
                                                      cfg.instanceAid, cfg.privileges, parameters,
                                                      cfg.makeSelectable);

        List names = new ArrayList(sequence.names);
        List apdus = new ArrayList(sequence.apdus);
        names.add("INSTALL [for install" + (cfg.makeSelectable ? " and make selectable" : "") + "]");
        apdus.add(installApdu);

        out.heading("The " + apdus.size() + " packets this job would send");
        for (int i = 0; i < apdus.size(); i++)
        {
            byte[] apdu = (byte[]) apdus.get(i);
            String line = pad(String.valueOf(names.get(i)), 34) + " " + MslCore.hex(apdu);
            out.step(line);
            report.installLine(line);
        }

        // An APDU that cannot fit one envelope is not a card problem, it is this
        // run's problem, and it is caught here rather than at packet 40 of 60.
        byte[] oversized = null;
        for (int i = 0; i < apdus.size(); i++)
        {
            if (!MslCapLoad.fitsOneEnvelope((byte[]) apdus.get(i)))
            {
                oversized = (byte[]) apdus.get(i);
                break;
            }
        }
        if (oversized != null)
        {
            out.error("One APDU is " + oversized.length + " bytes, above the "
                      + MslCapLoad.MAX_OTA_APDU + " a single SMS-PP envelope can carry. Lower the "
                      + "LOAD block size; if it is the INSTALL itself, shorten the install "
                      + "parameters.");
            record(MslReport.FAIL, "an APDU does not fit one envelope",
                   "Nothing was sent. " + oversized.length + " bytes against a limit of "
                   + MslCapLoad.MAX_OTA_APDU + ".");
            return;
        }

        if (!cfg.confirmIrreversible)
        {
            out.heading("Dry run");
            out.info("Nothing was sent. Every packet above was built, and the load file was "
                     + (sdkAgrees ? "confirmed against the SDK's own reading of this CAP."
                                  : "NOT confirmed against the SDK - see the warning above."));
            out.info("Tick the irreversible-change box on the Run tab to actually load and "
                     + "install. Prefer a disposable test card: this cannot be undone.");
            record(MslReport.UNKNOWN, "dry run - nothing was sent",
                   "The " + apdus.size() + " packets above were built and printed. No card "
                   + "content was changed.");
            return;
        }

        if (!sdkAgrees)
        {
            out.error("Refusing to send: this tool's load file does not match the SDK's reading of "
                      + "the same CAP. One of the two is wrong, and an irreversible load is not "
                      + "the place to find out which.");
            record(MslReport.FAIL, "the load file disagrees with the SDK",
                   "Nothing was sent. The dry run above shows both readings.");
            return;
        }

        reset();
        wakeToolkit();

        Sender sender = new Sender(cfg.ramTar);
        out.heading("Sending " + apdus.size() + " secured packets to card manager TAR "
                    + MslCore.hex(cfg.ramTar));

        for (int i = 0; i < apdus.size(); i++)
        {
            String name = String.valueOf(names.get(i));
            Ram step = sender.exchange((byte[]) apdus.get(i));

            if (!step.packetAccepted())
            {
                out.error("STOPPED at " + name + ": " + step.describe());
                out.info(step.por == null
                    ? "No PoR at all. On this card family that is a counter below the card's, a "
                      + "wrong card manager key, or a TAR that is not the card manager."
                    : "The packet itself was refused, so the command inside it never ran.");
                record(MslReport.FAIL, "stopped at " + name, step.describe()
                       + ". The card may now hold a partly loaded package: delete the load file "
                       + "with the delete job before trying again, or the next INSTALL [for load] "
                       + "answers 6A80.");
                return;
            }
            if (step.inner == null)
            {
                out.warn(name + ": PoR 00, but the response carried no status word for the command "
                         + "inside it - so the card accepted the packet and this run cannot prove "
                         + "the command itself worked. Stopping rather than loading on top of it.");
                record(MslReport.UNCONFIRMED, "no inner status word at " + name,
                       "PoR 00 says the packet was accepted; it says nothing about the command.");
                return;
            }
            if (!step.inner.ok())
            {
                out.error("STOPPED at " + name + ": the card manager answered "
                          + MslCore.hexWord(step.inner.statusWord));
                explainInstallFailure(step.inner.statusWord);
                record(MslReport.FAIL, name + " answered "
                       + MslCore.hexWord(step.inner.statusWord),
                       "The packet was accepted (PoR 00) and the command inside it was refused.");
                return;
            }
            out.good(pad(name, 34) + " PoR 00, card SW "
                     + MslCore.hexWord(step.inner.statusWord));
        }

        out.heading("Registry check");
        boolean present = ramRegistryHolds(sender, MslCore.STATUS_APPLICATIONS, cfg.instanceAid);

        out.heading("What is proven, and what is not");
        out.info("Every packet was accepted and every command answered 9000. That means the card "
                 + "loaded the package and created the instance. It does NOT mean the MSL inside "
                 + "the parameters is enforced as it reads - nothing reads install parameters "
                 + "back, so run the discover or verify job against the applet's TAR next.");

        record(present ? MslReport.PASS : MslReport.UNCONFIRMED,
               "loaded and installed " + MslCore.hex(cfg.instanceAid)
               + (readBack == null ? " with no MSL field"
                                   : " with MSL " + MslCore.hexByte(readBack.toByte())),
               present
                   ? "9000 on every step, and the instance is in the registry. The MSL is still "
                     + "only a claim until the verify job demonstrates it."
                   : "9000 on every step, but the registry read afterwards did not show the "
                     + "instance. Treat the install as unconfirmed and browse the card.");
    }

    /**
     * Asks the SDK the same two questions about this CAP and compares.
     *
     * Both answers are printed whichever way it goes, because that is what
     * makes a disagreement diagnosable rather than just fatal. A missing or
     * empty SDK hash counts as a disagreement: it means the cross-check did not
     * happen, and an unchecked load file is exactly what this method exists to
     * refuse.
     */
    private boolean sdkConfirmsLoadFile(MslCapLoad.Sequence sequence)
    {
        out.heading("Cross-checking the load file against the SDK");

        LoadSequence sdk;
        try
        {
            sdk = new LoadSequence(cfg.capPath);
        }
        catch (Exception e)
        {
            out.warn("The SDK's LoadSequence could not read this CAP: " + e.getMessage()
                     + " - so this tool's reading of it is unchecked.");
            return false;
        }

        byte[] sdkAid;
        byte[] sdkHash;
        try
        {
            sdkAid = sdk.getLoadFileAID();
            sdkHash = sdk.getLoadFileDataBlockHash();
        }
        catch (RuntimeException e)
        {
            out.warn("The SDK would not say what it thinks this CAP's load file is: "
                     + e.getMessage());
            return false;
        }

        out.info("SDK load file AID   : " + MslCore.hex(sdkAid));
        out.info("SDK load file SHA-1 : " + MslCore.hex(sdkHash));

        if (sdkHash == null || sdkHash.length == 0)
        {
            out.warn("The SDK returned no load file hash, so there is nothing to compare this "
                     + "tool's load file against.");
            return false;
        }
        if (!MslCore.equal(sdkAid, sequence.elfAid))
        {
            out.error("The load file AID disagrees: this tool reads "
                      + MslCore.hex(sequence.elfAid) + " from the Header component, the SDK says "
                      + MslCore.hex(sdkAid) + ".");
            return false;
        }
        if (!MslCore.equal(sdkHash, sequence.loadFileHash))
        {
            out.error("The load file data block disagrees: same CAP, different SHA-1. The two "
                      + "readings differ somewhere in the component concatenation, and the card "
                      + "would be sent a load file whose hash does not match its own INSTALL "
                      + "[for load].");
            return false;
        }

        out.good("the SDK agrees: same load file AID, same SHA-1 over the whole load file");
        return true;
    }

    // ==================================================================
    // browse - what is actually on this card
    // ==================================================================

    /**
     * GET STATUS, over either road, read-only.
     *
     * Read-only is the whole point: the operator's question is "what is on this
     * card, and what is its AID" - usually before an install or a delete - and
     * the answer must not cost the card anything. Over OTA it does cost the OTA
     * counter one step per scope, which is unavoidable and reported.
     */
    private void browse()
    {
        List scopes = cfg.browseScopes();

        if (cfg.transport == MslConfig.TRANSPORT_ISD)
        {
            if (!openSession()) { return; }

            int found = 0;
            for (int i = 0; i < scopes.size(); i++)
            {
                found += listOverSecureChannel(((Integer) scopes.get(i)).intValue());
            }
            recordBrowse(found);
            return;
        }

        reset();
        wakeToolkit();

        Sender sender = new Sender(cfg.ramTar);
        int found = 0;
        for (int i = 0; i < scopes.size(); i++)
        {
            found += listOverRam(sender, ((Integer) scopes.get(i)).intValue());
        }

        out.heading("Counter");
        out.info("This run sent " + sender.sent + " packet(s). The last PoR reported "
                 + (sender.lastCardCounter == null ? "no counter value"
                                                   : MslCore.hex(sender.lastCardCounter))
                 + "; start the next run above that.");
        recordBrowse(found);
    }

    private void recordBrowse(int found)
    {
        record(found > 0 ? MslReport.PASS : MslReport.UNKNOWN,
               found > 0 ? found + " registry entr" + (found == 1 ? "y" : "ies") + " listed"
                         : "no registry entries were listed",
               found > 0
                   ? "Read-only: nothing on the card was changed."
                   : "Either the card refused GET STATUS, or the answer did not parse as a "
                     + "registry. Read the log: a PoR status other than 00 means the packet "
                     + "never reached the card manager.");
    }

    /**
     * One GET STATUS scope over OTA, following the card's 6310 continuations.
     *
     * 6310 is "there is more, ask again" - P2 bit b1 set. Each continuation is
     * another packet and another counter step, so the walk is bounded: a card
     * that answers 6310 forever would otherwise empty the counter space.
     */
    /**
     * The GET STATUS form this card accepts. -1 until one has answered, then
     * reused for every later scope and continuation in the run.
     */
    private int statusForm = -1;

    /**
     * GET STATUS over RAM, in a form this card will actually act on.
     *
     * Two things cards disagree about - the trailing Le and the response
     * format - and neither can be settled from a specification. The MCI/Hamrah
     * card answered 6F00 to the form every other card here accepts, and said
     * why in its own response: two commands executed where one was sent. It had
     * read the Le byte as the start of a second command, and the compact
     * response format reports only the last command's status, so the GET STATUS
     * answer was discarded.
     *
     * So the forms are tried in turn until one is accepted, and the one that
     * worked is remembered. A scope that is simply empty (6A88) still tells us
     * the form was understood, so it counts as success here.
     */
    private Ram getStatusOverRam(Sender sender, int scope, byte[] filter, boolean next)
    {
        if (statusForm >= 0)
        {
            return sender.exchange(MslCore.buildGetStatusApdu(scope, filter, next,
                MslCore.statusFormIsTlv(statusForm), MslCore.statusFormHasLe(statusForm)));
        }

        Ram answer = null;
        for (int i = 0; i < MslCore.STATUS_FORMS.length; i++)
        {
            int form = MslCore.STATUS_FORMS[i];
            byte[] apdu = MslCore.buildGetStatusApdu(scope, filter, next,
                MslCore.statusFormIsTlv(form), MslCore.statusFormHasLe(form));

            out.step("trying " + MslCore.statusFormLabel(form) + ": " + MslCore.hex(apdu));
            answer = sender.exchange(apdu);

            // A packet the card would not take says nothing about the form, so
            // there is no point walking the rest of them.
            if (!answer.packetAccepted() || answer.inner == null) { return answer; }

            int status = answer.inner.statusWord;
            if (status == 0x9000 || status == 0x6310 || status == 0x6A88)
            {
                statusForm = form;
                out.good("this card wants GET STATUS " + MslCore.statusFormLabel(form));
                return answer;
            }
            out.warn("the card answered " + MslCore.hexWord(status) + " to that form"
                     + extraCommands(answer));
        }
        return answer;
    }

    /**
     * The card's own evidence that an APDU carried more than one command.
     *
     * The compact RAM response counts the commands the card executed. More than
     * one from a script carrying one means the card read trailing bytes as
     * another command - which is exactly how a stray Le byte throws away the
     * answer to the command that mattered.
     */
    private String extraCommands(Ram answer)
    {
        if (answer == null || answer.inner == null || answer.inner.commands <= 1) { return ""; }

        return " - and reported " + answer.inner.commands + " commands executed where one was "
            + "sent, so it read trailing bytes as a second command";
    }

    private int listOverRam(Sender sender, int scope)
    {
        out.heading("GET STATUS - " + MslCore.statusScopeLabel(scope) + " (over RAM)");

        int total = 0;
        boolean next = false;

        for (int round = 0; round < 8; round++)
        {
            Ram answer = getStatusOverRam(sender, scope, new byte[0], next);
            if (!answer.packetAccepted())
            {
                out.error(answer.describe());
                return total;
            }
            if (answer.inner == null)
            {
                out.warn("PoR 00 with no response data: the card manager executed nothing this "
                         + "run can read. A card that answers this to GET STATUS is usually "
                         + "refusing card content management to this key set.");
                return total;
            }

            int status = answer.inner.statusWord;
            if (status == 0x6A88)
            {
                // An empty section, not a failure: the card understood the
                // command and has nothing in this scope.
                out.info("6A88: the card has nothing in this scope - an empty registry section, "
                         + "not an error.");
                return total;
            }
            if (status != 0x9000 && status != 0x6310)
            {
                out.error("the card manager answered " + MslCore.hexWord(status)
                          + " to GET STATUS" + extraCommands(answer));
                out.info("Every GET STATUS form this tool knows was refused. The key set reaches "
                         + "the card manager - the packet was accepted - so this is the card "
                         + "refusing card content management to it, not a transport problem.");
                return total;
            }

            total += printRegistry(answer.inner.data, scope);

            if (status != 0x6310) { return total; }

            out.info("6310: the card has more entries in this scope, asking for the next ones");
            next = true;
        }

        out.warn("stopped after 8 continuations - the card kept saying 6310. The listing above is "
                 + "incomplete.");
        return total;
    }

    /**
     * One GET STATUS scope through the SCP02 secure channel.
     *
     * The two scopes the SDK's own StatusType names are the ones this script has
     * always used, and they go through the SDK's sequence - which handles the
     * 6310 chaining itself. The issuer security domain scope has no proven
     * constant here, so it goes as an APDU built by MslCore and parsed by it
     * too; if a card answers nothing to that, the log says so rather than the
     * run pretending the ISD is absent.
     */
    private int listOverSecureChannel(int scope)
    {
        out.heading("GET STATUS - " + MslCore.statusScopeLabel(scope) + " (over SCP02)");

        if (scope == MslCore.STATUS_ISSUER_SECURITY_DOMAIN)
        {
            byte[] apdu = MslCore.buildGetStatusApdu(scope, new byte[0], false, false);
            GenericISOCommand command = new GenericISOCommand("GET STATUS");
            command.cla(apdu[0] & 0xFF).ins(apdu[1] & 0xFF).p1(apdu[2] & 0xFF).p2(apdu[3] & 0xFF);

            byte[] data = new byte[apdu[4] & 0xFF];
            System.arraycopy(apdu, 5, data, 0, data.length);
            command.data(data).le(0x00);

            ISOResponse response = sendSecure(command);
            int status = response.getStatusWord();
            if (status != 0x9000 && status != 0x6310)
            {
                out.warn("GET STATUS (issuer security domain) answered " + word(status));
                return 0;
            }
            return printRegistry(response.getResponseData(), scope);
        }

        GetStatusCommand.StatusType type =
            scope == MslCore.STATUS_APPLICATIONS
                ? GetStatusCommand.StatusType.APPLICATIONS_INCLUDING_SECURITY_DOMAINS
                : GetStatusCommand.StatusType.EXECUTABLE_LOAD_FILES_AND_EXECUTABLE_MODULES;

        GetStatusCommand command = new GetStatusCommand();
        command.statusType(type);
        command.deprecatedResponseFormat();

        GetStatusSequence sequence = new GetStatusSequence(command);
        ISOResponse response = runSecureCommandSequence(sequence);
        int status = response.getStatusWord();

        if (status != 0x9000 && status != 0x6310)
        {
            if (status == 0x6A88)
            {
                out.info("6A88: the card has nothing in this scope.");
            }
            else
            {
                out.warn("GET STATUS (" + type + ") answered " + word(status));
            }
            return 0;
        }

        // Parsed by the SDK here rather than by MslCore: on this road the SDK
        // has already reassembled the chained response, and its RegistryData is
        // the reading MslScript's install job has always used.
        GetStatusResponse parsed =
            new GetStatusResponse(command, sequence.getCompleteResponseData());
        List entries = parsed.getAllRegistryData();

        for (int i = 0; i < entries.size(); i++)
        {
            RegistryData entry = (RegistryData) entries.get(i);
            if (!entry.hasAID()) { continue; }

            int lifeCycle = entry.hasLifeCycleState() ? (entry.getLifeCycleState()[0] & 0xFF) : -1;
            out.info(MslCore.hex(entry.getAID())
                     + (lifeCycle < 0 ? ""
                        : "  life cycle " + MslCore.hexByte(lifeCycle) + " ("
                          + MslCore.lifeCycleName(scope, lifeCycle) + ")"));
            report.note(MslCore.statusScopeLabel(scope) + ": " + MslCore.hex(entry.getAID()));
        }
        out.info(entries.size() + " entr" + (entries.size() == 1 ? "y" : "ies"));
        return entries.size();
    }

    /** Prints one GET STATUS response, whichever format the card used. */
    private int printRegistry(byte[] data, int scope)
    {
        if (data == null || data.length == 0)
        {
            out.info("no registry data came back for this scope");
            return 0;
        }

        List entries;
        try
        {
            entries = MslCore.parseRegistry(data, scope);
        }
        catch (RuntimeException e)
        {
            out.warn("the registry data did not parse: " + e.getMessage());
            out.info("raw: " + MslCore.hex(data));
            return 0;
        }

        for (int i = 0; i < entries.size(); i++)
        {
            MslCore.Registry entry = (MslCore.Registry) entries.get(i);
            out.info(entry.describe(scope));
            report.note(MslCore.statusScopeLabel(scope) + ": " + entry.describe(scope));

            for (int j = 0; j < entry.modules.size(); j++)
            {
                out.info("    module " + MslCore.hex((byte[]) entry.modules.get(j)));
            }
        }

        if (entries.isEmpty())
        {
            out.info("raw: " + MslCore.hex(data));
            out.warn("the card answered, but nothing in the answer reads as a registry entry");
        }
        return entries.size();
    }

    /** True when a GET STATUS over RAM, filtered on this AID, finds it. */
    private boolean ramRegistryHolds(Sender sender, int scope, byte[] aid)
    {
        Ram answer = getStatusOverRam(sender, scope, aid, false);

        if (!answer.packetAccepted() || answer.inner == null)
        {
            out.warn("the registry could not be read back: " + answer.describe());
            return false;
        }
        if (answer.inner.statusWord != 0x9000 && answer.inner.statusWord != 0x6310)
        {
            out.warn("GET STATUS for " + MslCore.hex(aid) + " answered "
                     + MslCore.hexWord(answer.inner.statusWord));
            return false;
        }

        List entries = MslCore.parseRegistry(answer.inner.data, scope);
        for (int i = 0; i < entries.size(); i++)
        {
            MslCore.Registry entry = (MslCore.Registry) entries.get(i);
            if (MslCore.equal(entry.aid, aid))
            {
                out.good(entry.describe(scope));
                if (entry.lifeCycle == 0x03)
                {
                    out.warn("INSTALLED but not SELECTABLE: the applet will not answer a SELECT by "
                             + "AID and is not reachable by its TAR either - OTA answers 09 (TAR "
                             + "unknown). Nothing about its MSL can be tested in this state.");
                }
                return true;
            }
        }
        out.warn(MslCore.hex(aid) + " is not in the registry listing that came back");
        return false;
    }

    // ==================================================================
    // delete - remove an instance or a package
    // ==================================================================

    /**
     * DELETE [card content], over either road.
     *
     * Irreversible, and worse than irreversible for a package: with the related
     * objects option a single DELETE takes the load file and every instance made
     * from it. So the job reads the registry first and says exactly what it
     * found at that AID, and refuses to send when the AID is not there at all -
     * a DELETE at an AID the card does not have can only answer 6A88, and an
     * operator who typed one digit wrong wants to hear that before the send,
     * not after.
     */
    private void deleteObject()
    {
        // Over a contact channel DELETE is a case 4 command and carries its Le;
        // inside a secured packet it must not, or the card reads that byte as
        // the start of another command (which is what it did to GET STATUS).
        boolean overSecureChannel = cfg.transport == MslConfig.TRANSPORT_ISD;
        byte[] apdu = MslCore.buildDeleteApdu(cfg.deleteAid, cfg.deleteRelatedObjects,
                                              overSecureChannel);

        out.heading("What would be deleted");
        out.info("AID              : " + MslCore.hex(cfg.deleteAid));
        out.info("related objects  : " + (cfg.deleteRelatedObjects
            ? "YES - the object AND everything related to it. For a package that is the load file "
              + "and every applet instance made from it."
            : "no - that object only. A package with instances will be refused 6985 or 6A80."));
        out.info("DELETE APDU      : " + MslCore.hex(apdu));
        report.installLine("DELETE " + MslCore.hex(apdu));

        if (cfg.transport == MslConfig.TRANSPORT_ISD)
        {
            if (!openSession()) { return; }

            out.heading("What is at that AID now");
            int before = listOverSecureChannel(MslCore.STATUS_APPLICATIONS)
                + listOverSecureChannel(MslCore.STATUS_LOAD_FILES_AND_MODULES);
            out.info(before + " registry entr" + (before == 1 ? "y" : "ies")
                     + " read; check the AID above appears in the listing.");

            if (!confirmedForDelete()) { return; }

            // The SDK's typed DeleteCommand for the plain case, which this
            // script has used since the install job existed; the cascade has no
            // proven setter here, so it goes as the APDU printed above through
            // the same secure channel.
            int status = cfg.deleteRelatedObjects
                ? sendSecure(asGeneric("DELETE", apdu)).getStatusWord()
                : sendSecure(new DeleteCommand().aid(cfg.deleteAid)).getStatusWord();

            reportDelete(status);
            return;
        }

        reset();
        wakeToolkit();

        Sender sender = new Sender(cfg.ramTar);

        out.heading("What is at that AID now");
        boolean isApplication = ramRegistryHolds(sender, MslCore.STATUS_APPLICATIONS,
                                                 cfg.deleteAid);
        boolean isLoadFile = isApplication
            || ramRegistryHolds(sender, MslCore.STATUS_LOAD_FILES_AND_MODULES, cfg.deleteAid);

        if (!isApplication && !isLoadFile)
        {
            out.error("Refusing to send: " + MslCore.hex(cfg.deleteAid) + " is in neither the "
                      + "application nor the load file registry, so a DELETE for it can only "
                      + "answer 6A88. Run the browse job and check the AID.");
            record(MslReport.FAIL, "that AID is not on the card",
                   "Nothing was deleted. The registry listings above are what the card reported.");
            return;
        }
        if (isLoadFile && !isApplication && !cfg.deleteRelatedObjects)
        {
            out.warn(MslCore.hex(cfg.deleteAid) + " is a load file. If any instance was made from "
                     + "it, this DELETE is refused unless the related-objects box is ticked.");
        }

        if (!confirmedForDelete()) { return; }

        out.heading("Sending DELETE to card manager TAR " + MslCore.hex(cfg.ramTar));
        Ram answer = sender.exchange(apdu);

        if (!answer.packetAccepted())
        {
            out.error(answer.describe());
            record(MslReport.FAIL, "the DELETE packet was not accepted", answer.describe());
            return;
        }
        if (answer.inner == null)
        {
            out.warn("PoR 00, but no status word for the DELETE itself came back, so this run "
                     + "cannot say whether it happened. Browse the card to find out.");
            record(MslReport.UNCONFIRMED, "no inner status word for the DELETE",
                   "PoR 00 says the packet was accepted; it says nothing about the command.");
            return;
        }
        reportDelete(answer.inner.statusWord);
    }

    /** The irreversible-change gate, said once for both roads. */
    private boolean confirmedForDelete()
    {
        if (cfg.confirmIrreversible) { return true; }

        out.heading("Dry run");
        out.info("Nothing was sent. Tick the irreversible-change box on the Run tab to actually "
                 + "delete. There is no undo, and a deleted instance takes its install parameters "
                 + "- the MSL this tool measures - with it.");
        record(MslReport.UNKNOWN, "dry run - nothing was deleted",
               "The DELETE APDU above was built and printed only.");
        return false;
    }

    private void reportDelete(int status)
    {
        if (status == 0x9000)
        {
            out.good("DELETE returned 9000: " + MslCore.hex(cfg.deleteAid) + " is gone"
                     + (cfg.deleteRelatedObjects ? ", with everything related to it." : "."));
            record(MslReport.PASS, "deleted " + MslCore.hex(cfg.deleteAid),
                   cfg.deleteRelatedObjects
                       ? "With related objects: the load file and every instance made from it."
                       : "That object only.");
            return;
        }

        out.error("DELETE returned " + MslCore.hexWord(status));
        if (status == 0x6A88)
        {
            out.info("6A88: the card does not have that AID.");
        }
        else if (status == 0x6985)
        {
            out.info("6985: the card refuses this deletion in its current state - usually a load "
                     + "file that still has instances (tick the related-objects box) or an applet "
                     + "the issuer has made undeletable.");
        }
        else if (status == 0x6982)
        {
            out.info("6982: the channel is not authenticated for this. Over OTA that means the "
                     + "key set reaching the card manager is not allowed to delete.");
        }
        record(MslReport.FAIL, "DELETE returned " + MslCore.hexWord(status),
               "Nothing was deleted.");
    }

    /** A hand-built APDU as a generic command, for the paths with no typed SDK equivalent. */
    private GenericISOCommand asGeneric(String name, byte[] apdu)
    {
        GenericISOCommand command = new GenericISOCommand(name);
        command.cla(apdu[0] & 0xFF).ins(apdu[1] & 0xFF).p1(apdu[2] & 0xFF).p2(apdu[3] & 0xFF);

        byte[] data = new byte[apdu[4] & 0xFF];
        System.arraycopy(apdu, 5, data, 0, data.length);
        command.data(data).le(0x00);
        return command;
    }

    private static String pad(String text, int width)
    {
        StringBuilder out = new StringBuilder(text);
        while (out.length() < width) { out.append(' '); }
        return out.toString();
    }


    // ==================================================================
    // Tasks 2 and 3 - prove an MSL, or find one
    // ==================================================================

    /**
     * Probing, over envelopes this script frames itself.
     *
     * Nothing about the inference changes: MslProbing drives it exactly as it
     * does in the Python port and in the self-test, and only the transport
     * underneath is different.
     */
    private void probe()
    {
        reset();
        wakeToolkit();

        Sender sender = new Sender();
        MslProbing.Oracle oracle = new MslProbing.Oracle(sender, cfg.probeBudget, cfg.silentDrop);
        MslProbing.Ceiling ceiling = cfg.ceiling();

        out.heading("Probing TAR " + MslCore.hex(cfg.targetTar));
        out.info("reachable ceiling: " + ceiling.describe());
        out.info("Each probe carries one inert byte. An MSL rejection happens before the applet "
                 + "sees the data, so nothing meaningful is sent - and must not be, because a TAR "
                 + "in the B0xxxx range is an RFM instance that executes what it is handed.");

        if (cfg.mode == MslConfig.MODE_VERIFY)
        {
            out.info("claimed MSL: " + cfg.claimedMsl.describe());
            MslProbing.Verification result = MslProbing.verify(oracle, cfg.claimedMsl, ceiling);

            out.heading("Result");
            out.lines(result.describe());
            report.probes(oracle.results);
            for (int i = 0; i < result.notes.size(); i++)
            {
                report.note(String.valueOf(result.notes.get(i)));
            }
            record(result.passed ? MslReport.PASS : MslReport.FAIL,
                   "MSL " + MslCore.hexByte(cfg.claimedMsl.toByte()) + " - "
                   + cfg.claimedMsl.describe(),
                   result.passed
                       ? "Accepted at exactly that level, and rejected 0A one notch below on "
                         + "every axis there was something below to try."
                       : "The card does not demonstrably enforce this. A packet weaker than the "
                         + "claim that was ACCEPTED means the applet is reachable below its "
                         + "stated level.");
        }
        else
        {
            MslProbing.Discovery result = MslProbing.discover(oracle, ceiling);

            out.heading("Result");
            out.lines(result.describe());
            report.probes(oracle.results);
            for (int i = 0; i < result.notes.size(); i++)
            {
                report.note(String.valueOf(result.notes.get(i)));
            }

            if (result.msl == null)
            {
                record(MslReport.UNKNOWN, "MSL not determined",
                       "The probes did not pin down a level. Read the table: a run that went "
                       + "INCONCLUSIVE early usually means the toolkit was dormant, the counter "
                       + "was below the card's, or the TAR is not an installed applet.");
            }
            else
            {
                record(result.confirmed ? MslReport.PASS : MslReport.UNCONFIRMED,
                       "MSL " + MslCore.hexByte(result.msl.toByte()) + " - "
                       + result.msl.describe(),
                       result.confirmed
                           ? "Confirmed by check probes at the level and one notch below each axis."
                           : "The check probes disagreed, so this card is not enforcing the MSL "
                             + "field by field. The level above is a measurement, not a claim.");
            }
        }

        out.heading("Counter");
        out.info("This run sent " + oracle.results.size() + " packet(s). The card's counter has "
                 + "moved on accordingly; the last PoR reported "
                 + (sender.lastCardCounter == null ? "no counter value"
                                                   : MslCore.hex(sender.lastCardCounter))
                 + ". Start the next run above that.");
    }

    /**
     * TERMINAL PROFILE, or a clear warning that it was skipped.
     *
     * Every job that sends a secured packet needs this, not just probing: a
     * card whose toolkit has never been told what the terminal supports ignores
     * SMS-PP DOWNLOAD whoever sent it, so an ota-install would read as a dead
     * card manager key.
     */
    private void wakeToolkit()
    {
        if (cfg.sendTerminalProfile)
        {
            sendTerminalProfile();
        }
        else
        {
            out.warn("TERMINAL PROFILE was not sent. A card whose toolkit has never been told "
                     + "what the terminal supports ignores every envelope - and does it silently, "
                     + "which reads exactly like a wrong key.");
        }
    }

    private void sendTerminalProfile()
    {
        GenericISOCommand profile = new GenericISOCommand("TERMINAL PROFILE");
        profile.cla(0x80).ins(0x10).p1(0x00).p2(0x00).data(cfg.terminalProfile).noLe();

        ISOResponse response = send(profile);
        int status = response.getStatusWord();

        if (status == 0x9000 || (status & 0xFF00) == 0x9100)
        {
            out.good("TERMINAL PROFILE " + MslCore.hex(cfg.terminalProfile) + " -> "
                     + word(status));
        }
        else
        {
            out.warn("TERMINAL PROFILE " + MslCore.hex(cfg.terminalProfile) + " -> " + word(status)
                     + " - the card did not accept it, so every envelope below may be ignored. "
                     + "Some cards want a different profile: 02 and FFFF are both known to work "
                     + "where FF alone does not.");
        }
    }

    private void record(String verdict, String what)
    {
        record(verdict, what, "");
    }

    /**
     * One verdict, in every place a verdict belongs: the log window, the
     * machine-readable line, the certificate and the report.
     *
     * Saying it once here rather than at each call site is what stops the four
     * from ever disagreeing - a report that says PASS over a log that says FAIL
     * is worse than no report.
     */
    private void record(String verdict, String what, String detail)
    {
        String line = "MSL-RESULT|" + cfg.cardLabel + "|" + MslCore.hex(cfg.targetTar) + "|"
            + jobName().toUpperCase() + "|" + verdict + "|" + what;

        out.verdict(verdict, what, detail);
        out.line(line);

        if (report != null) { report.verdict(verdict, what, detail); }

        try
        {
            getCertificate().storeAdditionalInformation("MSL result", line);
        }
        catch (RuntimeException ignored) { }
    }

    /**
     * Writes the report, and says where it went.
     *
     * A failure to write is reported and not thrown: the run already happened,
     * and losing the log window on top of losing the file helps nobody.
     */
    private void writeReport()
    {
        if (report == null || cfg == null || !cfg.writeReport) { return; }

        try
        {
            File written = report.writeTo(cfg.reportFolder);
            out.good("report written to " + written.getAbsolutePath());
            out.info("the CSV beside it has one row per probe, plus a result row");

            try
            {
                getCertificate().storeAdditionalInformation("MSL report",
                                                            written.getAbsolutePath());
            }
            catch (RuntimeException ignored) { }
        }
        catch (IOException e)
        {
            out.error("the report could not be written: " + e.getMessage());
        }
    }

    /**
     * One probe: build the packet with the SDK, frame the envelope here, send it
     * as a plain APDU, read the response packet back.
     */
    private final class Sender implements MslProbing.Sender
    {
        private final SCP80Security security;
        private final byte[] tar;
        private long counter;
        byte[] lastCardCounter;

        /**
         * What the next packet carries, and what the last one got back.
         *
         * A probe carries one inert byte and the caller only wants the outcome;
         * a RAM step carries a real card content management APDU and the caller
         * needs the whole PoR, because the status word of the command inside it
         * lives in the response data. Rather than two packet builders, there is
         * one, with the payload set per call and the PoR kept where exchange()
         * can read it.
         */
        private byte[] payload = { 0x00 };
        private MslCore.Por lastPor;
        int sent;

        Sender()
        {
            this(cfg.targetTar);
        }

        Sender(byte[] tar)
        {
            // KIc (ciphering) first, KID (integrity) second - independent keys.
            security = new DefaultSCP80Security(cfg.effectiveKicKey(), cfg.otaKey);
            this.tar = tar;
            counter = cfg.startCounter;
        }

        /**
         * One RAM step: the APDU goes to this sender's TAR inside a secured
         * packet, and what comes back is the PoR plus the status word of the
         * command the card manager executed.
         */
        Ram exchange(byte[] apdu)
        {
            byte[] previous = payload;
            try
            {
                payload = apdu;
                lastPor = null;
                MslProbing.Result result = send(cfg.ramProbe());
                return new Ram(result, lastPor);
            }
            finally
            {
                payload = previous;
            }
        }

        public MslProbing.Result send(MslProbing.Probe probe)
        {
            long value = counter;
            if (probe.counter == MslCore.COUNTER_ONE_HIGHER && lastCardCounter != null)
            {
                value = toLong(lastCardCounter) + 1;
            }
            counter = value + 1;

            try
            {
                // Both SPI octets are packed by the SDK's own typed constructor
                // rather than shifted together here; MslSelfTest asserts the two
                // agree on octet 1 for all 32 combinations.
                int spi = UlChoices.spiValue(probe.integrity, probe.cipher, probe.counter,
                                             UlChoices.porMode(cfg.porMode),
                                             UlChoices.porSmsType(cfg.porSmsType));
                int header = cfg.otaKeyHeader();

                SCP80SecurityParameters parameters =
                    new SCP80SecurityParameters(spi, header, header);
                SecuredCommandPacket packet = SecuredCommandPacketFactory.secureForSMS(
                    security, parameters, tar, counterBytes(value), payload);

                byte[] envelope = MslCore.buildEnvelope(packet.toByteArray(), "0000000000");

                GenericISOCommand command = new GenericISOCommand("ENVELOPE (SMS-PP DOWNLOAD)");
                command.cla(0x80).ins(0xC2).p1(0x00).p2(0x00).data(envelope).noLe();

                sent++;
                ISOResponse response = MslScript.this.send(command);
                return read(probe, response);
            }
            catch (RuntimeException e)
            {
                // A probe that could not be built or sent is inconclusive, not
                // rejected. Scoring it as a rejection would push an axis
                // threshold up and hand back a confidently wrong MSL.
                String[] classified = MslProbing.classify(-1, false);
                MslProbing.Result result = new MslProbing.Result(probe, classified[0], -1,
                    "could not be sent: " + e.getClass().getSimpleName() + " " + e.getMessage());
                out.step(result.describe());
                return result;
            }
        }

        private MslProbing.Result read(MslProbing.Probe probe, ISOResponse response)
        {
            byte[] data = response.getResponseData();
            int status = response.getStatusWord();

            // 61 xx means the card has xx bytes of response (the PoR) waiting and
            // wants a GET RESPONSE to hand them over - the normal T=0 way a
            // DELIVER-REPORT PoR comes back after ENVELOPE. Pull it, chaining on
            // further 61 xx. Without this the PoR is left on the card and the run
            // reads as "no PoR" even though the card answered correctly. (The
            // Python reader's transmit() already did this; the UL path needed it
            // too - found on the first live UL run.)
            int guard = 0;
            while ((status & 0xFF00) == 0x6100 && guard < 16)
            {
                guard++;
                GenericISOCommand getResponse = new GenericISOCommand("GET RESPONSE");
                getResponse.cla(0x00).ins(0xC0).p1(0x00).p2(0x00).noData().noLc().le(status & 0xFF);

                ISOResponse more = MslScript.this.send(getResponse);
                byte[] chunk = more.getResponseData();
                if (chunk != null && chunk.length > 0)
                {
                    data = (data == null || data.length == 0) ? chunk : concat(data, chunk);
                }
                status = more.getStatusWord();
            }

            // 91 xx means the card has a proactive command waiting rather than an
            // answer in hand (PoR via SMS-SUBMIT / network return). Fetch it as a
            // fallback for cards that route the PoR that way.
            if ((data == null || data.length == 0) && (status & 0xFF00) == 0x9100)
            {
                GenericISOCommand fetch = new GenericISOCommand("FETCH");
                fetch.cla(0x80).ins(0x12).p1(0x00).p2(0x00).noData().noLc().le(status & 0xFF);

                ISOResponse fetched = MslScript.this.send(fetch);
                data = fetched.getResponseData();
            }

            MslCore.Por por = MslCore.parsePor(data);
            lastPor = por;
            MslProbing.Result result;

            if (por == null)
            {
                String[] classified = MslProbing.classify(-1, false);
                String note = classified[1];
                if (status != 0x9000)
                {
                    note = note + " (ENVELOPE answered " + word(status) + ")";
                }
                result = new MslProbing.Result(probe, classified[0], -1, note);
            }
            else
            {
                if (por.counter != null && por.counter.length == 5)
                {
                    lastCardCounter = por.counter;
                }
                String[] classified = MslProbing.classify(por.status, true);
                result = new MslProbing.Result(probe, classified[0], por.status, classified[1]);
            }

            out.step(result.describe());
            return result;
        }

        private byte[] concat(byte[] a, byte[] b)
        {
            byte[] out = new byte[a.length + b.length];
            System.arraycopy(a, 0, out, 0, a.length);
            System.arraycopy(b, 0, out, a.length, b.length);
            return out;
        }

        private byte[] counterBytes(long value)
        {
            byte[] bytes = new byte[5];
            for (int i = 4; i >= 0; i--)
            {
                bytes[i] = (byte) (value & 0xFF);
                value >>= 8;
            }
            return bytes;
        }

        private long toLong(byte[] value)
        {
            long out = 0;
            for (int i = 0; i < value.length; i++)
            {
                out = (out << 8) | (value[i] & 0xFF);
            }
            return out;
        }
    }

    /**
     * What one RAM step got back.
     *
     * Two status words matter and they are not the same thing. The PoR status
     * says what happened to the PACKET - 00 means the MAC was good, the counter
     * was accepted and the TAR resolved. The inner status word, inside the PoR's
     * response data, says what the card manager did with the command. An INSTALL
     * the card refused with 6A80 arrives inside a perfectly good PoR 00, so a
     * run that checked only the PoR would report a load that never happened.
     */
    private static final class Ram
    {
        final MslProbing.Result result;
        final MslCore.Por por;
        final MslCore.RamResponse inner;

        Ram(MslProbing.Result result, MslCore.Por por)
        {
            this.result = result;
            this.por = por;
            this.inner = (por == null) ? null : MslCore.parseRamResponse(por.responseData);
        }

        boolean packetAccepted()
        {
            return por != null && por.status == 0x00;
        }

        String describe()
        {
            if (por == null)
            {
                return "no PoR came back" + (result == null ? "" : " - " + result.note);
            }
            return "PoR status " + MslCore.hexByte(por.status)
                + (inner == null ? ", no command status in it" : ", " + inner.describe());
        }
    }

    // ------------------------------------------------------------------
    // Resource plumbing - SCP02Script inherits getResource() from AbstractScript
    // ------------------------------------------------------------------

    private Frame parentFrame()
    {
        try
        {
            if (isResourceAvailable(TerminalResourceKeys.PARENT_FRAME))
            {
                return (Frame) getResource(TerminalResourceKeys.PARENT_FRAME);
            }
        }
        catch (RuntimeException ignored) { }
        return null;
    }

    private PrintWriter scriptOutput()
    {
        try
        {
            return getScriptOutput();
        }
        catch (RuntimeException e)
        {
            return null;
        }
    }
}
