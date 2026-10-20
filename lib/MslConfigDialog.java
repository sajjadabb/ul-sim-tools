import aspects.applications.threeg.scp80.CipherMode;
import aspects.applications.threeg.scp80.CounterMode;
import aspects.applications.threeg.scp80.IntegrityLevel;
import aspects.applications.threeg.scp80.PoRMode;
import aspects.applications.threeg.scp80.PoRSMSType;

import nl.collis.api.simulation.gp.scp02.SecurityLevel;

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
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;

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
public final class MslConfigDialog extends JFrame
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
        "install - put an applet on the card with a chosen MSL" });
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

    // -- report ----------------------------------------------------------
    private final JCheckBox writeReportCheck = new JCheckBox(
        "Write an HTML and CSV report when the run finishes", true);
    private final JTextField reportFolderField = new JTextField(30);
    private final JButton reportBrowseButton = new JButton("...");

    // -- run -------------------------------------------------------------
    private final JCheckBox matchCheck = new JCheckBox(
        "These values match the SIM currently in the reader");
    private final JCheckBox changeCheck = new JCheckBox(
        "I accept that this run installs an applet on that SIM");

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

        row = wide(job, c, row, steps(installSelected()
            ? new String[] {
                "Open an SCP02 secure channel to the ISD.",
                "Optionally DELETE an existing instance with the same AID.",
                "Load the CAP if the executable load file is not already on the card.",
                "INSTALL [for install and make selectable] with the parameters built on the MSL tab.",
                "Confirm in the registry that the instance is SELECTABLE - an applet that is not "
                + "selectable is unreachable by its TAR, and OTA answers 09 rather than anything "
                + "about security." }
            : new String[] {
                "Send TERMINAL PROFILE so the card's toolkit is awake.",
                "Send one secured packet per probe, each carrying a single inert byte.",
                "Read the response status: 0A means below the MSL, anything else means the packet "
                + "got past the security gate.",
                "Infer the MSL, then check the inference with further probes." }));

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
                "Installing changes the card and there is no undo. An MSL cannot be edited "
                + "afterwards - changing it means deleting the instance and installing again. "
                + "Only the install job needs this."));
            row = wide(safety, c, row, hint("The two probing jobs are read-only in the sense that "
                + "matters: they install nothing and delete nothing. They do move the card's OTA "
                + "counter, which is why the probe budget is a hard stop."));
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
                                otaKeyField, otaKicKeyField };
        for (int i = 0; i < fields.length; i++)
        {
            fields[i].getDocument().addDocumentListener(listener);
        }

        JComboBox[] combos = { modeCombo, isdAidCombo, scp02KvnCombo, securityLevelCombo,
                               privilegesCombo, mslIntegrityCombo, mslCipherCombo, mslCounterCombo,
                               tarCombo, priorityCombo, timersCombo, menuTextCombo, channelsCombo, installFormatCombo,
                               targetTarCombo, otaKvnCombo, otaAlgCombo, porModeCombo, porSmsCombo,
                               terminalProfileCombo, claimedIntegrityCombo, claimedCipherCombo,
                               claimedCounterCombo, budgetCombo };
        for (int i = 0; i < combos.length; i++)
        {
            combos[i].addActionListener(action);
            editorOf(combos[i], listener);
        }

        JCheckBox[] boxes = { writeReportCheck, noMslCheck, deleteExistingCheck,
                              makeSelectableCheck, localApduCheck,
                              terminalProfileCheck, allowCipheringCheck, allowOneHigherCheck, silentDropCheck,
                              matchCheck, changeCheck };
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
        return MslConfig.MODE_DISCOVER;
    }

    private boolean installSelected()
    {
        return selectedMode() == MslConfig.MODE_INSTALL;
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
    private JLabel steps(String[] items)
    {
        StringBuilder html = new StringBuilder("<html><div style='width:" + TEXT_WIDTH
                                               + "px'><ol>");
        for (int i = 0; i < items.length; i++)
        {
            html.append("<li style='margin-bottom:4px'>").append(escape(items[i])).append("</li>");
        }
        html.append("</ol></div></html>");

        JLabel label = new JLabel(html.toString());
        label.setForeground(new Color(50, 60, 70));
        label.setBorder(BorderFactory.createEmptyBorder(2, 2, 8, 2));
        return label;
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
