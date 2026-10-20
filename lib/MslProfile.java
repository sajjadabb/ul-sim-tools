import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

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
public final class MslProfile
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
