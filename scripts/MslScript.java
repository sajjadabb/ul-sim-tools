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
        if (cfg.mode == MslConfig.MODE_INSTALL)  { return "install"; }
        if (cfg.mode == MslConfig.MODE_VERIFY)   { return "verify"; }
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
            if (cfg.mode == MslConfig.MODE_INSTALL)
            {
                install();
            }
            else
            {
                probe();
            }
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
        private long counter;
        byte[] lastCardCounter;

        Sender()
        {
            // KIc (ciphering) first, KID (integrity) second - independent keys.
            security = new DefaultSCP80Security(cfg.effectiveKicKey(), cfg.otaKey);
            counter = cfg.startCounter;
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
                    security, parameters, cfg.targetTar, counterBytes(value),
                    new byte[] { 0x00 });

                byte[] envelope = MslCore.buildEnvelope(packet.toByteArray(), "0000000000");

                GenericISOCommand command = new GenericISOCommand("ENVELOPE (SMS-PP DOWNLOAD)");
                command.cla(0x80).ins(0xC2).p1(0x00).p2(0x00).data(envelope).noLe();

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
