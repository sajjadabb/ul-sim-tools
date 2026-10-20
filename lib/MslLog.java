import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.Font;
import java.io.PrintWriter;

import javax.swing.JFrame;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.SwingUtilities;

/**
 * A live log window, plus an echo into the platform's own script output.
 *
 * A probing run is a sequence of one-line answers and the interesting part is
 * watching them arrive - a walk that stops after two probes has already told
 * you something. The tool's own output panel is written to as well, so the
 * transcript survives after the window is closed.
 *
 * Everything is posted to the event dispatch thread, because a script runs on
 * its own thread and Swing is not thread-safe.
 */
public final class MslLog
{
    private final PrintWriter output;
    private JFrame frame;
    private JTextArea area;

    public MslLog(String title, PrintWriter output)
    {
        this.output = output;
        build(title);
    }

    private void build(final String title)
    {
        Runnable create = new Runnable()
        {
            public void run()
            {
                area = new JTextArea(28, 110);
                area.setEditable(false);
                area.setFont(new Font("Monospaced", Font.PLAIN, 12));

                frame = new JFrame(title);
                frame.getContentPane().add(new JScrollPane(area), BorderLayout.CENTER);
                frame.setPreferredSize(new Dimension(980, 560));
                frame.pack();
                frame.setLocationByPlatform(true);
                frame.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
                frame.setVisible(true);
            }
        };

        if (SwingUtilities.isEventDispatchThread()) { create.run(); }
        else
        {
            try { SwingUtilities.invokeAndWait(create); }
            catch (Exception ignored) { /* head-less or CLI: the output panel still gets everything */ }
        }
    }

    public void heading(String text)
    {
        line("");
        line("=== " + text + " ===");
    }

    public void info(String text)  { line("     " + text); }
    public void step(String text)  { line("  -  " + text); }
    public void good(String text)  { line("  ok " + text); }
    public void warn(String text)  { line("  !  " + text); }
    public void error(String text) { line("  X  " + text); }

    public void lines(java.util.List texts)
    {
        for (int i = 0; i < texts.size(); i++) { info(String.valueOf(texts.get(i))); }
    }

    public void line(final String text)
    {
        if (output != null)
        {
            output.println(text);
            output.flush();
        }
        if (area == null) { return; }

        SwingUtilities.invokeLater(new Runnable()
        {
            public void run()
            {
                area.append(text + "\n");
                area.setCaretPosition(area.getDocument().getLength());
            }
        });
    }

    /** Leaves the window open so the run can be read after the script ends. */
    /**
     * The verdict, in a block that cannot be missed in a scrolling log.
     *
     * A run that ends in a wall of probe lines leaves the reader to work out
     * what happened. This says it once, plainly, in the words the report uses.
     */
    public void verdict(String verdict, String headline, String detail)
    {
        line("");
        line("========================================================================");
        line("  " + verdict + "   " + (headline == null ? "" : headline));
        if (detail != null && detail.length() > 0)
        {
            line("  " + detail);
        }
        line("========================================================================");
        line("");
    }

    public void markFinished()
    {
        line("");
        line("--- run finished; this window can be closed ---");
    }
}
