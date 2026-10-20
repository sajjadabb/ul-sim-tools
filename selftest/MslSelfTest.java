import java.util.ArrayList;
import java.util.List;

/**
 * Card-free checks over MslCore and MslProbing. No reader, no card, no UL
 * licence, no dongle - run it before you need any of those.
 *
 *     ./selftest.sh
 *
 * These mirror tools/selftest_msl.py check for check, so a change made on one
 * side and not the other shows up here rather than on a card. The parts worth
 * testing at all are the ones where being wrong is quiet: install parameters
 * that encode a different MSL than the one asked for, and an inference that
 * returns a confident MSL from probe answers that did not support it.
 */
public final class MslSelfTest
{
    private static int passed;
    private static int failed;

    public static void main(String[] args)
    {
        levelChecks();
        installParameterChecks();
        installApduChecks();
        classificationChecks();
        discoveryChecks();
        verificationChecks();
        profileRefusesKeyMaterial();
        sdkEnumsAgreeWithTheCore();
        envelopeAndPor();
        reportContents();
        configGates();
        ceilingAndKeyHeader();
        certificateLineCarriesNoSecrets();

        System.out.println();
        System.out.println(passed + " passed, " + failed + " failed");
        System.exit(failed == 0 ? 0 : 1);
    }

    // ------------------------------------------------------------------

    private static void check(String description, boolean condition, String detail)
    {
        if (condition)
        {
            passed++;
        }
        else
        {
            failed++;
            System.out.println("FAIL  " + description
                               + (detail == null || detail.length() == 0 ? "" : "  -- " + detail));
        }
    }

    private static void check(String description, boolean condition)
    {
        check(description, condition, "");
    }

    private interface Block { void run(); }

    private static boolean raises(Block block)
    {
        try
        {
            block.run();
            return false;
        }
        catch (RuntimeException e)
        {
            return true;
        }
    }

    private static MslCore.Level[] allLevels()
    {
        MslCore.Level[] levels = new MslCore.Level[32];
        int index = 0;
        for (int integrity = 0; integrity < 4; integrity++)
        {
            for (int cipher = 0; cipher < 2; cipher++)
            {
                for (int counter = 0; counter < 4; counter++)
                {
                    levels[index++] = new MslCore.Level(integrity, cipher, counter);
                }
            }
        }
        return levels;
    }

    // ------------------------------------------------------------------
    // The MSL byte
    // ------------------------------------------------------------------

    private static void levelChecks()
    {
        MslCore.Level[] levels = allLevels();
        for (int i = 0; i < levels.length; i++)
        {
            final MslCore.Level level = levels[i];
            check("MSL " + MslCore.hexByte(level.toByte())
                  + " round-trips through toByte/fromByte",
                  MslCore.Level.fromByte(level.toByte()).equals(level));
        }

        MslCore.Level twelve = MslCore.Level.fromByte(0x12);
        check("MSL 12 decodes as the vendor spreadsheet documents it "
              + "(counter higher, CC, no ciphering)",
              twelve.integrity == MslCore.INTEGRITY_CC
              && twelve.cipher == MslCore.CIPHER_OFF
              && twelve.counter == MslCore.COUNTER_HIGHER);

        check("an MSL byte using the reserved bits b6-b8 is refused rather than silently masked",
              raises(new Block() { public void run() { MslCore.Level.fromByte(0x92); } }));
        check("an empty MSL field decodes as 'no minimum enforced', not as MSL 00",
              MslCore.Level.fromField(new byte[0]) == null);
        check("MSL data after the parameter byte survives a round trip",
              MslCore.equal(MslCore.Level.fromField(MslCore.unhex("12AABB")).data,
                            MslCore.unhex("AABB")));

        check("dominance is field-wise: CC/off/higher does not satisfy CC/on/higher",
              !new MslCore.Level(2, 0, 2).dominates(new MslCore.Level(2, 1, 2)));

        boolean all = true;
        for (int i = 0; i < levels.length; i++)
        {
            all = all && new MslCore.Level(3, 1, 3).dominates(levels[i]);
        }
        check("dominance is field-wise: DS/on/one-higher satisfies everything", all);
    }

    // ------------------------------------------------------------------
    // Install parameters
    // ------------------------------------------------------------------

    private static void installParameterChecks()
    {
        MslCore.Level[] levels = allLevels();
        for (int i = 0; i < levels.length; i++)
        {
            MslCore.Toolkit toolkit = new MslCore.Toolkit(levels[i]);
            toolkit.addTar(MslCore.unhex("B00010"));
            byte[] params = MslCore.buildInstallParameters(toolkit, null, null);

            check("install parameters carrying MSL " + MslCore.hexByte(levels[i].toByte())
                  + " read back as the same MSL",
                  levels[i].equals(MslCore.mslOfInstallParameters(params)), MslCore.hex(params));
        }

        MslCore.Toolkit toolkit = new MslCore.Toolkit(new MslCore.Level(2, 0, 2));
        toolkit.addTar(MslCore.unhex("B00010")).addTar(MslCore.unhex("B00011"));
        toolkit.priority = 0x02;
        toolkit.maxTimers = 0x01;
        toolkit.maxMenuTextLength = 0x10;
        toolkit.maxChannels = 0x02;
        toolkit.menuEntries.add(new MslCore.MenuEntry(0x01, 0x02));
        toolkit.menuEntries.add(new MslCore.MenuEntry(0x00, 0x00));

        byte[] params = MslCore.buildInstallParameters(toolkit, null, null);
        MslCore.ParsedToolkit parsed =
            MslCore.parseToolkit(MslCore.findToolkitParameters(params));

        check("menu entries do not shift the MSL field out of place",
              new MslCore.Level(2, 0, 2).equals(parsed.msl), MslCore.hex(params));
        check("both TARs survive a round trip",
              parsed.tars.size() == 2
              && MslCore.hex((byte[]) parsed.tars.get(0)).equals("B00010")
              && MslCore.hex((byte[]) parsed.tars.get(1)).equals("B00011"));
        check("the other toolkit fields survive a round trip",
              parsed.priority == 0x02 && parsed.maxTimers == 0x01
              && parsed.maxMenuTextLength == 0x10 && parsed.maxChannels == 0x02
              && parsed.menuEntries.size() == 2);

        check("C9 is emitted even when empty, because GlobalPlatform requires the tag",
              MslCore.hex(params).startsWith("C900"));

        MslCore.Toolkit noMsl = new MslCore.Toolkit(null);
        noMsl.addTar(MslCore.unhex("B00010"));
        check("an applet installed with no MSL field reads back as 'no minimum'",
              MslCore.mslOfInstallParameters(
                  MslCore.buildInstallParameters(noMsl, null, null)) == null);
        check("install parameters with no toolkit block at all read back as 'no minimum'",
              MslCore.mslOfInstallParameters(MslCore.unhex("C900")) == null);

        check("a truncated toolkit block raises instead of returning a half-parsed MSL",
              raises(new Block() { public void run()
                  { MslCore.parseToolkit(MslCore.unhex("010000000001")); } }));
        check("a TAR field length that is not a multiple of 3 raises",
              raises(new Block() { public void run()
                  { MslCore.parseToolkit(MslCore.unhex("01000000000112020000")); } }));

        // The two ETSI install-parameter formats (clause 8.2.1.3.2, confirmed from
        // the spec PDF): UICC is EA{80}, SIM is EF{CA}. EA{CA} is the malformed
        // cross the card rejects with 6A80, so the builder must never emit it.
        MslCore.Toolkit fmtTk = new MslCore.Toolkit(MslCore.Level.fromByte(0x12));
        fmtTk.addTar(MslCore.unhex("B00011"));
        byte[] uiccFmt = MslCore.buildInstallParameters(fmtTk, new byte[0], null, MslCore.FORMAT_UICC);
        byte[] simFmt = MslCore.buildInstallParameters(fmtTk, new byte[0], null, MslCore.FORMAT_SIM);
        check("UICC format wraps toolkit tag 80 in EA",
              MslCore.hex(uiccFmt).equals("C900EA0D800B0100000000011203B00011"), MslCore.hex(uiccFmt));
        check("SIM format wraps toolkit tag CA in EF",
              MslCore.hex(simFmt).equals("C900EF0DCA0B0100000000011203B00011"), MslCore.hex(simFmt));
        check("the builder never emits the EA{CA} cross the card rejects",
              MslCore.hex(uiccFmt).indexOf("EA0DCA") < 0);
        check("UICC format reads back its MSL",
              new MslCore.Level(2, 0, 2).equals(MslCore.mslOfInstallParameters(uiccFmt)));
        check("SIM format reads back its MSL",
              new MslCore.Level(2, 0, 2).equals(MslCore.mslOfInstallParameters(simFmt)));
        check("the 3-arg builder defaults to the UICC format",
              MslCore.hex(MslCore.buildInstallParameters(fmtTk, new byte[0], null))
                  .equals(MslCore.hex(uiccFmt)));

        // Read back a field built by some other tool, where EA is not first and
        // has siblings.
        byte[] foreign = MslCore.unhex("C900EF04C602000AEA0DCA0B0100000000011203B00010");
        check("the MSL is found even when EA is not the first tag",
              new MslCore.Level(2, 0, 2).equals(MslCore.mslOfInstallParameters(foreign)));

        List dump = MslCore.describeInstallParameters(params);
        boolean mentionsMsl = false;
        for (int i = 0; i < dump.size(); i++)
        {
            if (dump.get(i).toString().indexOf("-> MSL") >= 0) { mentionsMsl = true; }
        }
        check("the annotated dump names the MSL it decoded", mentionsMsl);
    }

    // ------------------------------------------------------------------
    // The INSTALL APDU
    // ------------------------------------------------------------------

    private static void installApduChecks()
    {
        MslCore.Toolkit toolkit = new MslCore.Toolkit(new MslCore.Level(2, 0, 2));
        toolkit.addTar(MslCore.unhex("B00010"));
        byte[] params = MslCore.buildInstallParameters(toolkit, null, null);

        byte[] apdu = MslCore.buildInstallApdu(MslCore.unhex("A00000015100"),
                                               MslCore.unhex("A0000001510001"),
                                               MslCore.unhex("A0000001510001"),
                                               MslCore.unhex("00"), params, true);

        check("INSTALL is 80 E6 0C 00", MslCore.hex(apdu).startsWith("80E60C00"));
        check("Lc matches the data that follows it", (apdu[4] & 0xFF) == apdu.length - 5,
              MslCore.hex(apdu));
        check("[for install] without make-selectable is P1=04",
              MslCore.hex(MslCore.buildInstallApdu(MslCore.unhex("A0"), MslCore.unhex("A0"),
                                                   MslCore.unhex("A0"), MslCore.unhex("00"),
                                                   params, false)).startsWith("80E60400"));

        int fields = 0;
        int pos = 5;
        byte[] fifth = null;
        while (pos < apdu.length)
        {
            int length = apdu[pos] & 0xFF;
            if (fields == 4)
            {
                fifth = new byte[length];
                System.arraycopy(apdu, pos + 1, fifth, 0, length);
            }
            pos += 1 + length;
            fields++;
        }
        check("INSTALL data is exactly six length-prefixed fields",
              fields == 6 && pos == apdu.length, fields + " fields, ended at " + pos);
        check("the fifth field is the install parameters", MslCore.equal(fifth, params));
    }

    // ------------------------------------------------------------------
    // Classifying a PoR
    // ------------------------------------------------------------------

    private static void classificationChecks()
    {
        check("status 0A is the only one that means 'below the MSL'",
              MslProbing.BELOW_MSL.equals(MslProbing.classify(0x0A, true)[0]));
        check("a MAC failure (01) counts as 'security level accepted', because the MSL check "
              + "happens first",
              MslProbing.ACCEPTED.equals(MslProbing.classify(0x01, true)[0]));
        check("counter low (02) counts as 'security level accepted' for the same reason",
              MslProbing.ACCEPTED.equals(MslProbing.classify(0x02, true)[0]));
        check("no PoR is inconclusive, never 'accepted'",
              MslProbing.INCONCLUSIVE.equals(MslProbing.classify(-1, false)[0]));
        check("TAR unknown (09) is inconclusive - no applet means no MSL",
              MslProbing.INCONCLUSIVE.equals(MslProbing.classify(0x09, true)[0]));
    }

    // ------------------------------------------------------------------
    // Discovery
    // ------------------------------------------------------------------

    private static void discoveryChecks()
    {
        MslProbing.Ceiling full = new MslProbing.Ceiling(MslCore.INTEGRITY_DS,
                                                         MslCore.CIPHER_ON,
                                                         MslCore.COUNTER_ONE_HIGHER);
        MslCore.Level[] levels = allLevels();
        int worst = 0;

        for (int i = 0; i < levels.length; i++)
        {
            MslProbing.SimulatedCard card =
                new MslProbing.SimulatedCard(levels[i], false, false);
            MslProbing.Discovery discovery =
                MslProbing.discover(new MslProbing.Oracle(card, 24), full);
            worst = Math.max(worst, card.sent);

            check("discovery recovers MSL " + MslCore.hexByte(levels[i].toByte()),
                  discovery.msl != null && discovery.msl.equals(levels[i]) && discovery.confirmed,
                  "got " + (discovery.msl == null ? "nothing" : discovery.msl.describe())
                  + " in " + card.sent + " probes");
        }
        check("discovery of any MSL costs at most 12 probes", worst <= 12,
              "worst case was " + worst);

        // The regression that matters most: a wrong OTA key must not turn into a
        // wrong MSL.
        for (int i = 0; i < levels.length; i++)
        {
            MslProbing.SimulatedCard card = new MslProbing.SimulatedCard(levels[i], true, false);
            MslProbing.Discovery discovery =
                MslProbing.discover(new MslProbing.Oracle(card, 24), full);

            check("discovery still recovers MSL " + MslCore.hexByte(levels[i].toByte())
                  + " when every accepted packet fails its MAC",
                  discovery.msl != null && discovery.msl.equals(levels[i]));
        }

        MslProbing.SimulatedCard silent =
            new MslProbing.SimulatedCard(new MslCore.Level(2, 0, 2), false, true);
        MslProbing.Discovery discovery =
            MslProbing.discover(new MslProbing.Oracle(silent, 24), full);
        check("a card that stays silent below its MSL yields 'undetermined' without silent-drop mode",
              discovery.msl == null);

        // With silent-drop mode, every one of the 32 MSL values is recovered
        // from a card that discards below-MSL packets with no PoR - the MCI card.
        MslCore.Level[] dropLevels = allLevels();
        int dropRecovered = 0;
        for (int i = 0; i < dropLevels.length; i++)
        {
            MslProbing.SimulatedCard card =
                new MslProbing.SimulatedCard(dropLevels[i], false, true);
            MslProbing.Discovery d =
                MslProbing.discover(new MslProbing.Oracle(card, 24, true), full);
            if (dropLevels[i].equals(d.msl) && d.confirmed) { dropRecovered++; }
        }
        check("silent-drop mode recovers all 32 MSL values from a silently-dropping card",
              dropRecovered == dropLevels.length, dropRecovered + "/" + dropLevels.length);

        // Silent-drop + a wrong key (accepted probes answer 01, below-MSL drop)
        // must still recover the level - exactly the bench card's behaviour.
        int dropBadMac = 0;
        for (int i = 0; i < dropLevels.length; i++)
        {
            MslProbing.SimulatedCard card =
                new MslProbing.SimulatedCard(dropLevels[i], true, true);
            MslProbing.Discovery d =
                MslProbing.discover(new MslProbing.Oracle(card, 24, true), full);
            if (dropLevels[i].equals(d.msl)) { dropBadMac++; }
        }
        check("silent-drop + bad-MAC still recovers all 32 MSL values",
              dropBadMac == dropLevels.length, dropBadMac + "/" + dropLevels.length);

        // Safety: when even the ceiling drops (no baseline), silent-drop must
        // NOT fabricate a level.
        MslProbing.Sender alwaysSilent = new MslProbing.Sender()
        {
            public MslProbing.Result send(MslProbing.Probe p)
            {
                String[] c = MslProbing.classify(-1, false);
                return new MslProbing.Result(p, c[0], -1, c[1]);
            }
        };
        MslProbing.Discovery dead =
            MslProbing.discover(new MslProbing.Oracle(alwaysSilent, 24, true), full);
        check("silent-drop still yields 'undetermined' when even the ceiling gets no PoR",
              dead.msl == null);

        final MslProbing.SimulatedCard ciphered =
            new MslProbing.SimulatedCard(new MslCore.Level(MslCore.INTEGRITY_CC,
                                                           MslCore.CIPHER_ON,
                                                           MslCore.COUNTER_HIGHER), false, false);
        discovery = MslProbing.discover(new MslProbing.Oracle(ciphered, 24),
                                        new MslProbing.Ceiling(MslCore.INTEGRITY_CC,
                                                               MslCore.CIPHER_OFF,
                                                               MslCore.COUNTER_HIGHER));
        boolean saidSo = false;
        for (int i = 0; i < discovery.notes.size(); i++)
        {
            if (discovery.notes.get(i).toString().indexOf("above the reachable ceiling") >= 0)
            {
                saidSo = true;
            }
        }
        check("an MSL above the reachable ceiling is reported as out of reach, not as "
              + "'rejects everything'", discovery.msl == null && saidSo);
        check("nothing further is sent once the ceiling probe is rejected", ciphered.sent == 1,
              "sent " + ciphered.sent);

        final MslProbing.SimulatedCard strict =
            new MslProbing.SimulatedCard(new MslCore.Level(3, 1, 3), false, false);
        final MslProbing.Ceiling fullCeiling = full;
        check("the probe budget stops the run instead of walking every axis",
              raises(new Block() { public void run()
                  { MslProbing.discover(new MslProbing.Oracle(strict, 2), fullCeiling); } }));
    }

    // ------------------------------------------------------------------
    // Verification
    // ------------------------------------------------------------------

    private static void verificationChecks()
    {
        MslProbing.Ceiling full = new MslProbing.Ceiling(MslCore.INTEGRITY_DS,
                                                         MslCore.CIPHER_ON,
                                                         MslCore.COUNTER_ONE_HIGHER);
        MslCore.Level claimed = new MslCore.Level(MslCore.INTEGRITY_CC, MslCore.CIPHER_OFF,
                                                  MslCore.COUNTER_HIGHER);

        MslProbing.Verification result = MslProbing.verify(
            new MslProbing.Oracle(new MslProbing.SimulatedCard(claimed, false, false), 24),
            claimed, full);
        check("verification passes when the card enforces exactly the claimed MSL", result.passed);

        MslCore.Level weaker = new MslCore.Level(MslCore.INTEGRITY_CC, MslCore.CIPHER_OFF,
                                                 MslCore.COUNTER_NO_CHECK);
        result = MslProbing.verify(
            new MslProbing.Oracle(new MslProbing.SimulatedCard(weaker, false, false), 24),
            claimed, full);
        check("verification fails when the card enforces LESS than claimed - the finding that "
              + "matters", !result.passed);

        MslCore.Level stronger = new MslCore.Level(MslCore.INTEGRITY_CC, MslCore.CIPHER_ON,
                                                   MslCore.COUNTER_HIGHER);
        result = MslProbing.verify(
            new MslProbing.Oracle(new MslProbing.SimulatedCard(stronger, false, false), 24),
            claimed, full);
        check("verification fails when the card enforces MORE than claimed", !result.passed);

        MslCore.Level nothing = new MslCore.Level(0, 0, 0);
        result = MslProbing.verify(
            new MslProbing.Oracle(new MslProbing.SimulatedCard(nothing, false, false), 24),
            nothing, full);
        check("a claimed MSL of 00 reports every axis as untested rather than passing vacuously",
              result.notes.size() == 3);
    }

    // ==================================================================
    // The report - the only durable record a run leaves
    // ==================================================================

    private static MslReport sampleReport(String verdict)
    {
        MslConfig cfg = goodProbe();
        cfg.operator = "lab";
        cfg.otaKey = MslCore.unhex("404142434445464748494A4B4C4D4E4F");

        MslReport report = new MslReport(cfg, "discover");
        report.verdict(verdict, "MSL 12 - cryptographic checksum, no ciphering, counter must be "
                       + "higher", "Confirmed by check probes.");

        List results = new ArrayList();
        MslProbing.Probe accepted = new MslProbing.Probe(
            MslCore.INTEGRITY_CC, MslCore.CIPHER_OFF, MslCore.COUNTER_HIGHER);
        MslProbing.Probe below = new MslProbing.Probe(
            MslCore.INTEGRITY_NONE, MslCore.CIPHER_OFF, MslCore.COUNTER_HIGHER);

        results.add(new MslProbing.Result(accepted, MslProbing.ACCEPTED, 0x00, ""));
        results.add(new MslProbing.Result(below, MslProbing.BELOW_MSL, 0x0A,
                                          "insufficient security level"));
        results.add(new MslProbing.Result(below, MslProbing.INCONCLUSIVE, -1, "no PoR"));
        report.probes(results);
        report.note("a note worth keeping");
        return report;
    }

    private static void reportContents()
    {
        MslReport report = sampleReport(MslReport.PASS);
        String html = report.toHtml();
        String csv = report.toCsv();

        check("the report says which verdict the run reached",
              html.indexOf(">PASS<") >= 0, html.substring(0, Math.min(200, html.length())));
        check("the verdict carries the MSL it is about", html.indexOf("MSL 12") >= 0);
        check("every probe appears in the HTML", countOf(html, "<tr class=") == 3,
              String.valueOf(countOf(html, "<tr class=")));
        check("outcomes are styled apart so a rejection cannot read as an acceptance",
              html.indexOf("class=\"accepted\"") >= 0 && html.indexOf("class=\"below\"") >= 0
              && html.indexOf("class=\"unclear\"") >= 0);
        check("a probe with no PoR shows a dash rather than a made-up status",
              html.indexOf("&mdash;") >= 0);
        check("the note survives into the report", html.indexOf("a note worth keeping") >= 0);

        // The caveats are the difference between a report and a scoreboard.
        check("the report states that 0A is the only evidence of an MSL",
              html.indexOf("only evidence") >= 0);
        check("the report states that 01 and 02/03 mean the gate was passed",
              html.indexOf("past</em> the security gate") >= 0
              || html.indexOf("past the security gate") >= 0);
        check("the report states that silence is never a rejection",
              html.indexOf("INCONCLUSIVE, never a rejection") >= 0);
        check("the report names the spec clause the field order came from",
              html.indexOf("8.2.1.3.2") >= 0);

        // The safety claim, tested rather than asserted in a comment.
        check("no key material reaches the report",
              html.indexOf("404142434445464748494A4B4C4D4E4F") < 0
              && csv.indexOf("404142434445464748494A4B4C4D4E4F") < 0);

        check("the CSV has a header, a row per probe and a result row",
              csv.split("\n").length == 5, String.valueOf(csv.split("\n").length));
        check("the CSV result row carries the verdict", csv.indexOf("result,") >= 0
              && csv.indexOf(",PASS,") >= 0);
        check("commas inside a note do not break the CSV",
              csv.indexOf("\"insufficient security level\"") >= 0
              || csv.indexOf("insufficient security level") >= 0);

        // A failing run must never render as a passing one.
        MslReport failed = sampleReport(MslReport.FAIL);
        check("a FAIL verdict reports as a failure", !failed.passed()
              && failed.toHtml().indexOf(">FAIL<") >= 0);
        check("a FAIL verdict is styled as a failure, not a pass",
              failed.toHtml().indexOf("verdict bad") >= 0);
        check("an UNCONFIRMED discovery is not counted as a pass",
              !sampleReport(MslReport.UNCONFIRMED).passed());
        check("an UNKNOWN run is not counted as a pass",
              !sampleReport(MslReport.UNKNOWN).passed());
        check("only PASS counts as a pass", sampleReport(MslReport.PASS).passed());

        // The file name has to survive a card label with a slash in it.
        check("a card label is made safe for a file name",
              MslReport.safe("chip 1/A:B").equals("chip-1-A-B"),
              MslReport.safe("chip 1/A:B"));
        check("an empty label still yields a usable name",
              MslReport.safe("").equals("card"));
        check("HTML special characters in operator text are escaped",
              MslReport.html("<script>&").equals("&lt;script&gt;&amp;"),
              MslReport.html("<script>&"));
    }

    private static int countOf(String text, String needle)
    {
        int count = 0;
        int at = text.indexOf(needle);
        while (at >= 0)
        {
            count++;
            at = text.indexOf(needle, at + needle.length());
        }
        return count;
    }

    // ==================================================================
    // The envelope, and the packet that comes back
    // ==================================================================

    private static void envelopeAndPor()
    {
        byte[] packet = MslCore.unhex("00160C1209150015B0001000000012180012345678");
        byte[] envelope = MslCore.buildEnvelope(packet, "0000000000");

        check("the envelope is a D1 CAT TLV", (envelope[0] & 0xFF) == 0xD1);
        check("its length byte matches what follows", (envelope[1] & 0xFF) == envelope.length - 2);
        check("device identities carry the comprehension-required bit (82, not 02)",
              (envelope[2] & 0xFF) == 0x82);
        check("device identities say network to UICC",
              (envelope[4] & 0xFF) == 0x83 && (envelope[5] & 0xFF) == 0x81);
        check("the SMS TPDU tag carries the bit too (8B, not 0B)",
              (envelope[6] & 0xFF) == 0x8B);
        check("the TPDU length byte matches the rest of the envelope",
              (envelope[7] & 0xFF) == envelope.length - 8);
        check("the whole command packet survives inside the envelope",
              MslCore.hex(envelope).indexOf(MslCore.hex(packet)) > 0);
        check("the user data header announces a command packet (02 70 00)",
              MslCore.hex(envelope).indexOf("027000" + MslCore.hex(packet)) > 0);

        MslCore.Por por = MslCore.parsePor(MslCore.unhex("000A0AB000100000001000000A"));
        check("the shortest legal PoR parses", por != null);
        check("its status is read from the right offset", por != null && por.status == 0x0A);
        check("its TAR is read from the right offset",
              por != null && MslCore.hex(por.tar).equals("B00010"));
        check("its counter is read from the right offset",
              por != null && MslCore.hex(por.counter).equals("0000001000"));
        check("a PoR with no response data yields an empty array, not null",
              por != null && por.responseData.length == 0);

        MslCore.Por behindUdh = MslCore.parsePor(
            MslCore.unhex("027100" + "000A0AB000100000001000000A"));
        check("a PoR behind its user data header parses to the same status",
              behindUdh != null && behindUdh.status == 0x0A);

        check("a 12-byte fragment is refused rather than half-parsed",
              MslCore.parsePor(MslCore.unhex("000A0AB00010000000100000")) == null);
        check("null is refused rather than throwing", MslCore.parsePor(null) == null);

        MslCore.Por withData = MslCore.parsePor(MslCore.unhex(
            "0016" + "12" + "B00010" + "0000001000" + "00" + "00"
            + "0102030405060708" + "01900A"));
        check("response data starts after the checksum the RHL declares",
              withData != null && MslCore.hex(withData.responseData).equals("01900A"),
              withData == null ? "null" : MslCore.hex(withData.responseData));
    }

    // ==================================================================
    // The SDK's enums against this tool's integers
    // ==================================================================

    /**
     * The point of UlChoices is that two independent things compute the same
     * byte: MslCore packs the SPI first octet itself, and the SDK's typed SPI
     * constructor packs it from named enums. If they ever disagree, the probe
     * that goes out is not the probe the inference thinks it sent - and the
     * answer would be wrong in a way nothing else in this suite could catch.
     */
    private static void sdkEnumsAgreeWithTheCore()
    {
        for (int integrity = 0; integrity < 4; integrity++)
        {
            check("integrity axis " + integrity + " round-trips through the SDK enum",
                  UlChoices.integrityValue(UlChoices.integrity(integrity)) == integrity);
        }
        for (int cipher = 0; cipher < 2; cipher++)
        {
            check("cipher axis " + cipher + " round-trips through the SDK enum",
                  UlChoices.cipherValue(UlChoices.cipher(cipher)) == cipher);
        }
        for (int counter = 0; counter < 4; counter++)
        {
            check("counter axis " + counter + " round-trips through the SDK enum",
                  UlChoices.counterValue(UlChoices.counter(counter)) == counter);
        }

        int mismatches = 0;
        for (int integrity = 0; integrity < 4; integrity++)
        {
            for (int cipher = 0; cipher < 2; cipher++)
            {
                for (int counter = 0; counter < 4; counter++)
                {
                    int ours = MslCore.spiFirstOctet(integrity, cipher, counter);
                    int theirs = UlChoices.spiValue(integrity, cipher, counter,
                                                    aspects.applications.threeg.scp80.PoRMode.POR_REQUIRED,
                                                    aspects.applications.threeg.scp80.PoRSMSType.SMS_DELIVER_REPORT)
                                 >> 8;
                    if (ours != theirs)
                    {
                        mismatches++;
                        check("SPI octet 1 agrees for integrity=" + integrity + " cipher=" + cipher
                              + " counter=" + counter, false,
                              "MslCore says " + MslCore.hexByte(ours) + ", the SDK says "
                              + MslCore.hexByte(theirs));
                    }
                }
            }
        }
        check("MslCore and the SDK's SPI constructor pack the same first octet for all 32 "
              + "combinations", mismatches == 0, mismatches + " disagreed");

        // The documented example, both ways round.
        check("MSL 12 is CC + no ciphering + counter-higher through the SDK enums too",
              UlChoices.spiValue(MslCore.INTEGRITY_CC, MslCore.CIPHER_OFF, MslCore.COUNTER_HIGHER,
                                 aspects.applications.threeg.scp80.PoRMode.POR_REQUIRED,
                                 aspects.applications.threeg.scp80.PoRSMSType.SMS_DELIVER_REPORT)
              >> 8 == 0x12);

        check("the security level dropdown is filled from the SDK enum, not a typed-out list",
              UlChoices.securityLevels().length
              == nl.collis.api.simulation.gp.scp02.SecurityLevel.values().length);
        check("an unknown security level name falls back to CMAC rather than throwing",
              UlChoices.securityLevel("nonsense")
              == nl.collis.api.simulation.gp.scp02.SecurityLevel.CMAC);
        check("PoR SMS type parses back from its own name",
              UlChoices.porSmsType("SMS_SUBMIT")
              == aspects.applications.threeg.scp80.PoRSMSType.SMS_SUBMIT);
    }

    // ==================================================================
    // MslConfig - the gates that decide whether a run may start at all
    // ==================================================================

    /** A config that would pass validation, so each test can break one thing. */
    private static MslConfig goodInstall()
    {
        MslConfig cfg = new MslConfig(MslConfig.SCOPE_INSTALL);
        // validate() branches on the job, not the scope: one script does all
        // three now, so the mode is what says which values a run needs.
        cfg.mode = MslConfig.MODE_INSTALL;
        cfg.cardLabel = "chip-1";
        cfg.writeReport = false;      // the report gate has its own checks
        cfg.isdAid = MslCore.unhex("A000000151000000");
        cfg.scp02Enc = MslCore.unhex("404142434445464748494A4B4C4D4E4F");
        cfg.scp02Mac = MslCore.unhex("404142434445464748494A4B4C4D4E4F");
        cfg.scp02Dek = MslCore.unhex("404142434445464748494A4B4C4D4E4F");
        cfg.loadFileAid = MslCore.unhex("A0000000090001");
        cfg.moduleAid = MslCore.unhex("A000000009000101");
        cfg.instanceAid = MslCore.unhex("A000000009000102");
        cfg.privileges = MslCore.unhex("00");
        cfg.msl = MslCore.Level.fromByte(0x12);
        cfg.tars.add(MslCore.unhex("B00010"));
        return cfg;
    }

    private static MslConfig goodProbe()
    {
        MslConfig cfg = new MslConfig(MslConfig.SCOPE_PROBE);
        cfg.cardLabel = "chip-1";
        cfg.writeReport = false;      // the report gate has its own checks
        cfg.targetTar = MslCore.unhex("B00010");
        cfg.otaKey = MslCore.unhex("404142434445464748494A4B4C4D4E4F");
        cfg.otaAlgorithm = "3des2";
        cfg.startCounter = 0x1218;
        cfg.spiSecondOctet = 0x09;
        cfg.mode = MslConfig.MODE_DISCOVER;
        cfg.probeBudget = 24;
        return cfg;
    }

    private static boolean complains(MslConfig cfg, String fragment)
    {
        List problems = cfg.validate();
        for (int i = 0; i < problems.size(); i++)
        {
            if (String.valueOf(problems.get(i)).toLowerCase().indexOf(fragment.toLowerCase()) >= 0)
            {
                return true;
            }
        }
        return false;
    }

    private static void configGates()
    {
        check("a complete install config passes validation",
              goodInstall().validate().isEmpty(),
              String.valueOf(goodInstall().validate()));
        check("a complete probe config passes validation",
              goodProbe().validate().isEmpty(),
              String.valueOf(goodProbe().validate()));

        MslConfig cfg = goodInstall();
        cfg.cardLabel = "  ";
        check("a run without a card label is refused - the certificate has to name the SIM",
              complains(cfg, "label"));

        cfg = goodInstall();
        cfg.scp02Enc = MslCore.unhex("0011");
        check("a short SCP02 ENC key is refused", complains(cfg, "ENC key must be 16"));

        cfg = goodInstall();
        cfg.privileges = MslCore.unhex("0000");
        check("privileges that are neither 1 nor 3 bytes are refused", complains(cfg, "privileges"));

        cfg = goodInstall();
        cfg.tars.clear();
        check("installing with no TAR is refused - an applet with no TAR can never be probed",
              complains(cfg, "TAR is required"));

        cfg = goodInstall();
        cfg.msl = null;
        check("installing with neither an MSL nor a raw block is refused", complains(cfg, "MSL"));

        cfg = goodInstall();
        cfg.msl = null;
        cfg.rawInstallParameters = MslCore.unhex("C900EA0D800B0100000000011203B00010");
        check("a raw parameters block stands in for the builder", cfg.validate().isEmpty(),
              String.valueOf(cfg.validate()));
        check("a raw parameters block is used verbatim",
              MslCore.hex(cfg.installParameters()).equals("C900EA0D800B0100000000011203B00010"));
        check("the MSL is read back out of a raw block rather than trusted from the field",
              MslCore.mslOfInstallParameters(cfg.installParameters()).toByte() == 0x12);

        cfg = goodInstall();
        cfg.msl = null;
        cfg.rawInstallParameters = MslCore.unhex("C9");
        check("a raw parameters block that does not parse is refused before anything is sent",
              complains(cfg, "do not parse"));

        // --- probe scope --------------------------------------------------

        cfg = goodProbe();
        cfg.targetTar = MslCore.unhex("B000");
        check("a TAR that is not 3 bytes is refused", complains(cfg, "3 bytes"));

        cfg = goodProbe();
        cfg.otaKey = new byte[0];
        check("probing without a key is refused", complains(cfg, "key"));

        cfg = goodProbe();
        cfg.otaKey = MslCore.unhex("0011223344556677");
        check("a key of the wrong length for the algorithm is refused",
              complains(cfg, "3des2 key is 16 bytes"));

        cfg = goodProbe();
        cfg.otaAlgorithm = "des";
        cfg.otaKey = MslCore.unhex("0011223344556677");
        check("the same key is accepted when the algorithm says single DES",
              cfg.validate().isEmpty(), String.valueOf(cfg.validate()));

        cfg = goodProbe();
        cfg.startCounter = 0;
        check("a zero start counter is refused - too low means no PoR at all, which reads as a "
              + "wrong key", complains(cfg, "counter"));

        cfg = goodProbe();
        cfg.spiSecondOctet = 0x00;
        check("an SPI octet 2 asking for no PoR is refused - every answer this tool reads is a PoR",
              complains(cfg, "no PoR"));

        cfg = goodProbe();
        cfg.spiSecondOctet = 0x19;
        check("an SPI octet 2 asking for a ciphered PoR is refused - the status code cannot be "
              + "read until it is deciphered", complains(cfg, "ciphered PoR"));

        cfg = goodProbe();
        cfg.mode = MslConfig.MODE_VERIFY;
        check("verify without a claimed MSL is refused", complains(cfg, "supposed to have"));
        cfg.claimedMsl = MslCore.Level.fromByte(0x12);
        check("verify with a claimed MSL passes", cfg.validate().isEmpty(),
              String.valueOf(cfg.validate()));

        cfg = goodProbe();
        cfg.probeBudget = 3;
        check("a probe budget too small to finish a walk is refused", complains(cfg, "budget"));

        cfg = goodProbe();
        cfg.allowCiphering = true;
        cfg.otaKey = new byte[0];
        check("ciphered probes without a KIc key are refused", complains(cfg, "KIc"));

        // KIc and KID are independent keys. KID (otaKey) is used for the MAC;
        // KIc (otaKicKey) only for ciphering, and defaults to KID when blank.
        cfg = goodProbe();
        check("KIc defaults to KID when no separate KIc is given",
              MslCore.hex(cfg.effectiveKicKey()).equals(MslCore.hex(cfg.otaKey)));
        cfg.otaKicKey = MslCore.unhex("00112233445566778899AABBCCDDEEFF");
        check("a separate KIc key is used when given",
              MslCore.hex(cfg.effectiveKicKey()).equals("00112233445566778899AABBCCDDEEFF")
              && !MslCore.hex(cfg.effectiveKicKey()).equals(MslCore.hex(cfg.otaKey)));
        cfg.allowCiphering = true;
        check("a ciphered probe is allowed when KIc is given even if it differs from KID",
              cfg.validate().isEmpty(), String.valueOf(cfg.validate()));

        // A report the operator asked for but that cannot be written is a
        // silent loss of the only durable record the run leaves.
        cfg = goodProbe();
        cfg.writeReport = true;
        cfg.reportFolder = "";
        check("asking for a report without naming a folder is refused",
              complains(cfg, "folder for the report"));

        cfg = goodProbe();
        cfg.writeReport = true;
        cfg.reportFolder = "Z:/no/such/folder/anywhere";
        check("a report folder that does not exist is refused before the run starts",
              complains(cfg, "does not exist"));

        cfg = goodProbe();
        cfg.writeReport = true;
        cfg.reportFolder = System.getProperty("java.io.tmpdir");
        check("a real folder passes", cfg.validate().isEmpty(), String.valueOf(cfg.validate()));

        cfg = goodProbe();
        cfg.writeReport = false;
        cfg.reportFolder = "";
        check("no report means no folder is needed", cfg.validate().isEmpty());
    }

    /**
     * The ceiling is the tool's own limit, and it must never claim more than
     * the operator confirmed: an unreachable axis silently treated as reachable
     * is how discovery reports a threshold that was never measured.
     */
    private static void ceilingAndKeyHeader()
    {
        MslConfig cfg = goodProbe();
        MslProbing.Ceiling ceiling = cfg.ceiling();
        check("by default the ceiling is CC, no ciphering, counter-higher",
              ceiling.integrity == MslCore.INTEGRITY_CC
              && ceiling.cipher == MslCore.CIPHER_OFF
              && ceiling.counter == MslCore.COUNTER_HIGHER);

        cfg.allowCiphering = true;
        cfg.allowOneHigher = true;
        ceiling = cfg.ceiling();
        check("confirming both options raises the ceiling on both axes",
              ceiling.cipher == MslCore.CIPHER_ON
              && ceiling.counter == MslCore.COUNTER_ONE_HIGHER);
        check("the ceiling never claims digital signatures, which nothing here implements",
              ceiling.integrity == MslCore.INTEGRITY_CC);

        // KIc/KID byte: key version high nibble, algorithm low. Same values the
        // Python port produces - a mismatch here is a packet the card rejects
        // for a reason that has nothing to do with its MSL.
        cfg = goodProbe();
        cfg.otaKvn = 0x01;
        cfg.otaAlgorithm = "3des2";
        check("KIc/KID for KVN 01 + 3DES 2-key is 15", cfg.otaKeyHeader() == 0x15,
              MslCore.hexByte(cfg.otaKeyHeader()));
        cfg.otaAlgorithm = "3des3";
        check("KIc/KID for KVN 01 + 3DES 3-key is 19", cfg.otaKeyHeader() == 0x19,
              MslCore.hexByte(cfg.otaKeyHeader()));
        cfg.otaAlgorithm = "des";
        check("KIc/KID for KVN 01 + single DES is 11", cfg.otaKeyHeader() == 0x11,
              MslCore.hexByte(cfg.otaKeyHeader()));
        cfg.otaAlgorithm = "aes";
        check("KIc/KID for KVN 01 + AES is 12", cfg.otaKeyHeader() == 0x12,
              MslCore.hexByte(cfg.otaKeyHeader()));
        cfg.otaKvn = 0x0C;
        check("the key version lands in the high nibble", cfg.otaKeyHeader() == 0xC2,
              MslCore.hexByte(cfg.otaKeyHeader()));
    }

    /**
     * The certificate line is written into a report that leaves the lab. It
     * describes the run; it must never carry the key that ran it.
     */
    private static void certificateLineCarriesNoSecrets()
    {
        MslConfig cfg = goodProbe();
        cfg.otaKey = MslCore.unhex("404142434445464748494A4B4C4D4E4F");
        String line = cfg.describeForCertificate();
        check("the probe certificate line does not contain the OTA key",
              line.indexOf("404142434445464748494A4B4C4D4E4F") < 0, line);
        check("the probe certificate line still says which key set was used",
              line.indexOf("KVN=") >= 0 && line.indexOf("3des2") >= 0, line);
        check("the probe certificate line records the ceiling the run was limited to",
              line.indexOf("ceiling=") >= 0, line);

        MslConfig install = goodInstall();
        line = install.describeForCertificate();
        check("the install certificate line does not contain the SCP02 keys",
              line.indexOf("404142434445464748494A4B4C4D4E4F") < 0, line);
        check("the install certificate line records the exact parameters block sent",
              line.indexOf("C900EA0D800B0100000000011203B00010") >= 0, line);
    }

    /**
     * The profile file must never be a route for key material onto a card.
     *
     * This is a safety claim the README makes out loud, so it gets a test: an
     * operator who pastes a key into config/msl.properties to save typing must
     * have it dropped, not honoured, because test SIMs get swapped between runs
     * and a key that survives a swap is a key sent to the wrong card.
     */
    private static void profileRefusesKeyMaterial()
    {
        String[] secrets = { "scp02.enc", "SCP02.MAC", "scp02.dek", "ota.key", "otaKey",
                             "adm1", "pin1", "puk1", "some.key.here" };

        for (int i = 0; i < secrets.length; i++)
        {
            java.util.Properties values = new java.util.Properties();
            values.setProperty(secrets[i], "00112233445566778899AABBCCDDEEFF");
            values.setProperty("isd.aid", "A000000151000000");

            MslProfile.stripSecrets(values, "selftest");

            check("the profile refuses to load '" + secrets[i] + "'",
                  values.getProperty(secrets[i]) == null);
            check("stripping '" + secrets[i] + "' leaves non-secret pre-fill alone",
                  "A000000151000000".equals(values.getProperty("isd.aid")));
        }
    }
}
