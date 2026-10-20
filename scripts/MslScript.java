import aspects.applications.threeg.scp80.DefaultSCP80Security;
import aspects.applications.threeg.scp80.SCP80Security;
import aspects.applications.threeg.scp80.SCP80SecurityParameters;
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

import java.awt.Frame;
import java.io.File;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.List;

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
            summariseBrowse();
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

        summariseBrowse();

        out.heading("Counter");
        out.info("This run sent " + sender.sent + " packet(s). The last PoR reported "
                 + (sender.lastCardCounter == null ? "no counter value"
                                                   : MslCore.hex(sender.lastCardCounter))
                 + "; start the next run above that.");
        recordBrowse(found);
    }

    private void recordBrowse(int found)
    {
        if (found > 0 && browseIncomplete)
        {
            record(MslReport.UNCONFIRMED,
                   found + " registry entr" + (found == 1 ? "y" : "ies")
                   + " listed, but the listing is incomplete",
                   "Read-only: nothing on the card was changed. One or more scopes stopped "
                   + "answering part way through, so the card holds entries this run could not "
                   + "read. Do not treat the list above as everything that is on the card.");
            return;
        }

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
     * reused for every later scope and chunk in the run.
     */
    private int statusForm = -1;

    /**
     * One GET STATUS filtered to a single AID, read in full.
     *
     * A filtered listing is one entry, so it never chunks - which is why this
     * can be the simple two-packet pair rather than the walk a full listing
     * needs. The pair is still required: the card holds its answer behind
     * 61 xx and loses it when the packet ends.
     */
    private Ram getStatusFor(Sender sender, int scope, byte[] aid)
    {
        boolean tlv = MslCore.statusFormIsTlv(Math.max(statusForm, 0));
        boolean le = MslCore.statusFormHasLe(Math.max(statusForm, 0));
        byte[] apdu = MslCore.buildGetStatusApdu(scope, aid, false, tlv, le);

        Ram answer = sender.exchange(apdu);
        if (!answer.packetAccepted() || answer.inner == null) { return answer; }

        int length = MslCore.pendingLength(answer.inner.statusWord);
        if (length < 0) { return answer; }

        Ram read = readChunk(sender, apdu, length);
        return read == null ? answer : read;
    }

    /**
     * The card's own evidence that an APDU carried more than one command.
     *
     * The compact RAM response counts the commands the card executed. More than
     * one from a script carrying one means the card read trailing bytes as
     * another command - which is exactly how a stray Le byte throws away the
     * answer to the command that mattered.
     */
    private String extraCommands(Ram answer, int sent)
    {
        if (answer == null || answer.inner == null || answer.inner.commands <= sent)
        {
            return "";
        }
        return " - and reported " + answer.inner.commands + " commands executed where " + sent
            + " was sent, so it read trailing bytes as another command";
    }

    /**
     * The command script that re-walks a listing to chunk `chunk`.
     *
     * GET STATUS with P2=00 restarts the listing and GET STATUS with the
     * next-occurrence bit advances it by one chunk, so the whole walk fits in
     * one packet and is idempotent: every attempt starts from the beginning.
     * That is what makes this safe. A continuation sent on its own advances the
     * card's cursor and the chunk it was offering is gone - proven live, twice.
     */
    private byte[] listingScript(int scope, int chunk)
    {
        boolean tlv = MslCore.statusFormIsTlv(Math.max(statusForm, 0));
        boolean le = MslCore.statusFormHasLe(Math.max(statusForm, 0));

        byte[] script = MslCore.buildGetStatusApdu(scope, new byte[0], false, tlv, le);
        for (int i = 0; i < chunk; i++)
        {
            script = MslCore.commandScript(script,
                MslCore.buildGetStatusApdu(scope, new byte[0], true, tlv, le));
        }
        return script;
    }

    /**
     * One GET STATUS scope over OTA, chunk by chunk.
     *
     * Two packets per chunk: one to ask how long it is (the card answers
     * 61 xx), one to walk to it again and read it with a GET RESPONSE at the
     * end. The second packet repeats the walk because the pending data does not
     * survive the first - also proven live, when a GET RESPONSE sent alone in
     * the next packet answered 6F00 with nothing behind it.
     *
     * It costs a packet more per chunk than a card that keeps its response
     * would need, and it is the only shape that cannot silently lose entries.
     */
    private int listOverRam(Sender sender, int scope)
    {
        out.heading("GET STATUS - " + MslCore.statusScopeLabel(scope) + " (over RAM)");

        int total = 0;

        for (int chunk = 0; chunk < 16; chunk++)
        {
            // The form has to be settled before the script is built: the walk
            // and the GET RESPONSE that reads it must be the same shape, or the
            // card answers one and refuses the other.
            Ram probe;
            byte[] script;
            if (chunk == 0)
            {
                probe = firstChunkProbe(sender, scope);
                script = listingScript(scope, 0);
            }
            else
            {
                script = listingScript(scope, chunk);
                if (script.length + 5 > MslCapLoad.MAX_OTA_APDU)
                {
                    out.warn("the walk to chunk " + (chunk + 1) + " no longer fits one packet; "
                             + "the listing stops here and is incomplete");
                    browseIncomplete = true;
                    return total;
                }
                out.step("walking to chunk " + (chunk + 1) + ": " + MslCore.hex(script));
                probe = sender.exchange(script);
            }
            if (!probe.packetAccepted())
            {
                out.error(probe.describe());
                return endScope(total, chunk);
            }
            if (probe.inner == null)
            {
                out.warn("PoR 00 with no response data: the card manager executed nothing this "
                         + "run can read. A card that answers this to GET STATUS is usually "
                         + "refusing card content management to this key set.");
                return endScope(total, chunk);
            }

            int status = probe.inner.statusWord;
            if (status == 0x6A88)
            {
                out.info("6A88: the card has nothing more in this scope - an empty "
                         + "section, not an error.");
                return total;
            }

            Ram read = probe;
            int length = MslCore.pendingLength(status);
            if (length >= 0)
            {
                read = readChunk(sender, script, length);
                if (read == null) { return endScope(total, chunk); }
                status = read.inner.statusWord;
            }

            if (status != 0x9000 && status != 0x6310)
            {
                out.error("the card manager answered " + MslCore.hexWord(status)
                          + " to GET STATUS" + extraCommands(read, countCommands(script) + 1));
                if (statusForm < 0 && chunk == 0)
                {
                    out.info("Every GET STATUS form this tool knows was refused. The key set "
                             + "reaches the card manager - the packet was accepted - so this is "
                             + "the card refusing card content management to it, not a transport "
                             + "problem.");
                    return total;
                }
                return endScope(total, chunk);
            }

            total += printRegistry(read.inner.data, scope);

            if (status != 0x6310) { return total; }

            out.info("6310: the card has more entries in this scope, walking to the next chunk");
        }

        out.warn("stopped after 16 chunks - the card kept saying 6310");
        browseIncomplete = true;
        return total;
    }

    /**
     * Reads the chunk the walk ends on, with one correction.
     *
     * 6C yy and 67 yy both mean "wrong length, it is yy" and both are worth
     * following, because the walk is idempotent: asking again costs a packet
     * and nothing else. Null means the attempt failed and the caller should
     * stop.
     */
    private Ram readChunk(Sender sender, byte[] script, int length)
    {
        for (int attempt = 0; attempt < 2; attempt++)
        {
            out.info("reading " + length + " byte(s) with a GET RESPONSE at the end of the walk");

            Ram read = sender.exchange(MslCore.commandScript(script,
                                       MslCore.buildGetResponseApdu(length)));
            if (!read.packetAccepted() || read.inner == null)
            {
                out.error(read.describe());
                return null;
            }

            int corrected = MslCore.pendingLength(read.inner.statusWord);
            if (corrected < 0 || corrected == length) { return read; }

            out.info(MslCore.hexWord(read.inner.statusWord) + ": the card wants " + corrected
                     + " byte(s) asked for instead, so the walk is repeated with that length");
            length = corrected;
        }
        return null;
    }

    /** The first chunk, where the GET STATUS form is still being established. */
    private Ram firstChunkProbe(Sender sender, int scope)
    {
        if (statusForm >= 0)
        {
            return sender.exchange(listingScript(scope, 0));
        }

        Ram answer = null;
        for (int i = 0; i < MslCore.STATUS_FORMS.length; i++)
        {
            int form = MslCore.STATUS_FORMS[i];
            byte[] apdu = MslCore.buildGetStatusApdu(scope, new byte[0], false,
                MslCore.statusFormIsTlv(form), MslCore.statusFormHasLe(form));

            out.step("trying " + MslCore.statusFormLabel(form) + ": " + MslCore.hex(apdu));
            answer = sender.exchange(apdu);

            if (!answer.packetAccepted() || answer.inner == null) { return answer; }

            int status = answer.inner.statusWord;
            if (status == 0x9000 || status == 0x6310 || status == 0x6A88
                || MslCore.hasPendingData(status))
            {
                statusForm = form;
                out.good("this card wants GET STATUS " + MslCore.statusFormLabel(form));
                return answer;
            }
            out.warn("the card answered " + MslCore.hexWord(status) + " to that form"
                     + extraCommands(answer, 1));
        }
        return answer;
    }

    private int endScope(int total, int chunk)
    {
        if (chunk > 0 || total > 0)
        {
            out.warn("The listing for this scope is INCOMPLETE: " + total + " entr"
                     + (total == 1 ? "y was" : "ies were") + " read before the card stopped "
                     + "answering. What is above is real; what is missing is unknown.");
            browseIncomplete = true;
        }
        return total;
    }

    /** How many APDUs a script carries, for the "more commands than sent" note. */
    private static int countCommands(byte[] script)
    {
        int commands = 0;
        int pos = 0;
        while (pos + 5 <= script.length)
        {
            commands++;
            pos += 5 + ((script[pos] == 0x00 && (script[pos + 1] & 0xFF) == 0xC0)
                        ? 0 : (script[pos + 4] & 0xFF));
        }
        return commands;
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

            // Carried into the same shape the OTA road produces, so the summary
            // at the end reads identically whichever road the run took.
            MslCore.Registry collected = new MslCore.Registry();
            collected.aid = entry.getAID();
            collected.lifeCycle = lifeCycle;

            out.info(registryLine(collected, scope));
            report.note(MslCore.statusScopeLabel(scope) + ": "
                        + registryLine(collected, scope).trim());

            if (scope == MslCore.STATUS_APPLICATIONS) { browsedApplications.add(collected); }
            else { browsedLoadFiles.add(collected); }
        }
        out.info(entries.size() + " entr" + (entries.size() == 1 ? "y" : "ies"));
        return entries.size();
    }

    /**
     * True when a scope stopped answering part way through.
     *
     * A listing that is missing entries nobody can name is not a PASS: the
     * verdict says so, because an operator who deletes or installs on the
     * strength of an incomplete listing is working from a card that has more
     * on it than the report shows.
     */
    private boolean browseIncomplete;

    /** Every application entry this run read, and every load file, for the summary. */
    private final List browsedApplications = new ArrayList();
    private final List browsedLoadFiles = new ArrayList();

    /** Prints one GET STATUS response as a table, whichever format the card used. */
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

        if (entries.isEmpty())
        {
            out.info("raw: " + MslCore.hex(data));
            out.warn("the card answered, but nothing in the answer reads as a registry entry");
            return 0;
        }

        out.info(column("AID", 34) + column("life cycle", 32) + "privileges");
        out.info(pad("", 34 + 32 + 10).replace(' ', '-'));

        for (int i = 0; i < entries.size(); i++)
        {
            MslCore.Registry entry = (MslCore.Registry) entries.get(i);
            out.info(registryLine(entry, scope));
            report.note(MslCore.statusScopeLabel(scope) + ": " + registryLine(entry, scope).trim());

            for (int j = 0; j < entry.modules.size(); j++)
            {
                byte[] module = (byte[]) entry.modules.get(j);
                out.info("    module  " + MslCore.hex(module));
                report.note("    module " + MslCore.hex(module));
            }

            if (scope == MslCore.STATUS_APPLICATIONS)
            {
                browsedApplications.add(entry);
            }
            else if (MslCore.scopeCarriesModules(scope) || scope == MslCore.STATUS_LOAD_FILES)
            {
                browsedLoadFiles.add(entry);
            }
        }
        return entries.size();
    }

    private String registryLine(MslCore.Registry entry, int scope)
    {
        String lifeCycle = entry.lifeCycle < 0
            ? "not reported"
            : MslCore.lifeCycleName(scope, entry.lifeCycle)
              + " (" + MslCore.hexByte(entry.lifeCycle) + ")";

        return column(MslCore.hex(entry.aid), 34) + column(lifeCycle, 32)
            + (entry.privileges.length == 0 ? "" : MslCore.hex(entry.privileges));
    }

    /**
     * What the card actually holds, said once at the end.
     *
     * The per-scope tables are the evidence; this is the answer. The package
     * each instance came from is a GUESS and labelled as one: an instance AID
     * usually begins with its package's AID, and GlobalPlatform does not
     * require it, so nothing is decided on that basis - it is here because it
     * is what an operator reads the listing to find out.
     */
    private void summariseBrowse()
    {
        out.heading("What is on this card");

        int selectable = 0;
        int lockedOrInstalled = 0;
        for (int i = 0; i < browsedApplications.size(); i++)
        {
            MslCore.Registry entry = (MslCore.Registry) browsedApplications.get(i);
            if (entry.lifeCycle == 0x07) { selectable++; } else { lockedOrInstalled++; }
        }

        int modules = 0;
        for (int i = 0; i < browsedLoadFiles.size(); i++)
        {
            modules += ((MslCore.Registry) browsedLoadFiles.get(i)).modules.size();
        }

        out.info(browsedApplications.size() + " applet(s) and security domain(s): "
                 + selectable + " SELECTABLE, " + lockedOrInstalled + " not selectable");
        out.info(browsedLoadFiles.size() + " package(s) carrying " + modules + " module(s)");

        for (int i = 0; i < browsedLoadFiles.size(); i++)
        {
            MslCore.Registry loadFile = (MslCore.Registry) browsedLoadFiles.get(i);
            out.info("");
            out.info("package " + MslCore.hex(loadFile.aid)
                     + (loadFile.lifeCycle < 0 ? ""
                        : "  (" + MslCore.lifeCycleName(MslCore.STATUS_LOAD_FILES,
                                                        loadFile.lifeCycle) + ")"));

            for (int j = 0; j < loadFile.modules.size(); j++)
            {
                out.info("    module    " + MslCore.hex((byte[]) loadFile.modules.get(j)));
            }
            for (int j = 0; j < browsedApplications.size(); j++)
            {
                MslCore.Registry application = (MslCore.Registry) browsedApplications.get(j);
                if (startsWith(application.aid, loadFile.aid))
                {
                    out.info("    instance  " + MslCore.hex(application.aid) + "  "
                             + (application.lifeCycle < 0 ? ""
                                : MslCore.lifeCycleName(MslCore.STATUS_APPLICATIONS,
                                                        application.lifeCycle)));
                }
            }
        }

        if (!browsedLoadFiles.isEmpty() && !browsedApplications.isEmpty())
        {
            out.info("");
            out.info("Instances are matched to packages by AID prefix, which is a convention and "
                     + "not a rule - a card may hold an instance whose AID says nothing about "
                     + "where it came from. The module AID under each package is the one an "
                     + "INSTALL needs.");
        }

        out.info("");
        out.info("No MSL appears above, and none can: GET STATUS returns AIDs, life cycle and "
                 + "privileges, never install parameters. Run discover against an applet's TAR "
                 + "to measure what it enforces.");
    }

    private static boolean startsWith(byte[] value, byte[] prefix)
    {
        if (value == null || prefix == null || prefix.length == 0
            || value.length <= prefix.length)
        {
            return false;
        }
        for (int i = 0; i < prefix.length; i++)
        {
            if (value[i] != prefix[i]) { return false; }
        }
        return true;
    }

    /** True when a GET STATUS over RAM, filtered on this AID, finds it. */
    private boolean ramRegistryHolds(Sender sender, int scope, byte[] aid)
    {
        Ram answer = getStatusFor(sender, scope, aid);

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

    /**
     * A table cell that keeps its gap even when the value overflows the column.
     *
     * A 16-byte AID is 32 characters, and the first live listing ran its AIDs
     * straight into the life cycle beside them. Two spaces always, however wide
     * the value.
     */
    private static String column(String text, int width)
    {
        return pad(text, Math.max(width, text.length() + 2));
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
