import java.util.ArrayList;
import java.util.List;

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
public final class MslConfig
{
    public static final int SCOPE_INSTALL = 1;
    public static final int SCOPE_PROBE = 2;

    public static final int MODE_VERIFY = 1;
    public static final int MODE_DISCOVER = 2;
    public static final int MODE_INSTALL = 3;

    /**
     * Which of the three jobs this run does.
     *
     * The mode, not the scope, is what decides which values a run needs. There
     * is one script now - card content management and OTA probing in the same
     * class - so a fixed scope per script no longer exists to branch on.
     */
    public static boolean isInstall(int mode) { return mode == MODE_INSTALL; }

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
        return MslCore.buildInstallParameters(toolkit(), null, null, installFormat);
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

        if (mode == MODE_INSTALL)
        {
            validateInstall(problems);
        }
        else
        {
            validateProbe(problems);
        }
        return problems;
    }

    private void validateInstall(List problems)
    {
        if (isdAid.length < 5) { problems.add("The ISD AID is required (5 to 16 bytes)."); }
        if (scp02Enc.length != 16) { problems.add("The SCP02 ENC key must be 16 bytes."); }
        if (scp02Mac.length != 16) { problems.add("The SCP02 MAC key must be 16 bytes."); }
        if (scp02Dek.length != 16) { problems.add("The SCP02 DEK key must be 16 bytes."); }

        if (loadFileAid.length < 5) { problems.add("The executable load file AID is required."); }
        if (moduleAid.length < 5) { problems.add("The executable module AID is required."); }
        if (instanceAid.length < 5) { problems.add("The application instance AID is required."); }
        if (privileges.length != 1 && privileges.length != 3)
        {
            problems.add("Privileges are 1 byte (GlobalPlatform 2.1) or 3 bytes (2.2+).");
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
