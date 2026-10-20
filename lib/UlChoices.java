import aspects.applications.threeg.scp80.CipherMode;
import aspects.applications.threeg.scp80.CounterMode;
import aspects.applications.threeg.scp80.IntegrityLevel;
import aspects.applications.threeg.scp80.PoRMode;
import aspects.applications.threeg.scp80.PoRSMSType;
import aspects.applications.threeg.scp80.SPI;

import nl.collis.api.simulation.gp.scp02.SecurityLevel;

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
public final class UlChoices
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
