import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

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
public final class MslProbing
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
