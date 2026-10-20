import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

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
public final class MslCapLoad
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
