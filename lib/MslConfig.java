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
