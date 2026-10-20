import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

/**
 * The run, written down.
 *
 * A live log window is gone the moment the tool closes, and the UL certificate
 * is not something a colleague can open next week without the platform. This
 * builds two files instead: an HTML page to read, and a CSV row per probe to
 * grep or drop in a spreadsheet.
 *
 * Building and writing are separate on purpose. toHtml() and toCsv() are pure
 * string functions over what the run collected, so MslSelfTest can check the
 * verdict really does appear, that a key never does, and that a failed run is
 * never rendered as a pass - none of which needs a file system, let alone a
 * card.
 *
 * What a report must never do is flatter the run. A probe that got no answer is
 * INCONCLUSIVE here as everywhere else, an unconfirmed discovery says so in the
 * verdict line, and the caveat about what a PASS does and does not prove is
 * printed in the report rather than left in someone's memory.
 */
public final class MslReport
{
    /** Verdicts, in the order of how much they claim. */
    public static final String PASS = "PASS";
    public static final String FAIL = "FAIL";
    public static final String UNCONFIRMED = "UNCONFIRMED";
    public static final String UNKNOWN = "UNKNOWN";

    private final MslConfig config;
    private final String job;
    private final String startedAt;

    private String verdict = UNKNOWN;
    private String headline = "";
    private String detail = "";

    private final List probes = new ArrayList();      // MslProbing.Result
    private final List notes = new ArrayList();       // String
    private final List installLines = new ArrayList();// String

    public MslReport(MslConfig config, String job)
    {
        this.config = config;
        this.job = job;
        this.startedAt = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date());
    }

    public void verdict(String verdict, String headline, String detail)
    {
        this.verdict = verdict;
        this.headline = headline == null ? "" : headline;
        this.detail = detail == null ? "" : detail;
    }

    public void probes(List results)
    {
        if (results != null) { probes.addAll(results); }
    }

    public void note(String text)
    {
        if (text != null && text.length() > 0) { notes.add(text); }
    }

    public void installLine(String text)
    {
        if (text != null) { installLines.add(text); }
    }

    public String getVerdict() { return verdict; }

    /** True only for a verdict that actually claims the thing was demonstrated. */
    public boolean passed() { return PASS.equals(verdict); }

    // ------------------------------------------------------------------
    // CSV - one row per probe, then one summary row
    // ------------------------------------------------------------------

    public String toCsv()
    {
        StringBuilder out = new StringBuilder();
        out.append("kind,card,job,tar,probe,spi1,security,outcome,por,note\n");

        for (int i = 0; i < probes.size(); i++)
        {
            MslProbing.Result result = (MslProbing.Result) probes.get(i);
            out.append("probe,")
               .append(csv(config.cardLabel)).append(",")
               .append(csv(job)).append(",")
               .append(csv(MslCore.hex(config.targetTar))).append(",")
               .append(i + 1).append(",")
               .append(MslCore.hexByte(result.probe.spiFirstOctet())).append(",")
               .append(csv(security(result.probe))).append(",")
               .append(csv(result.outcome)).append(",")
               .append(result.status < 0 ? "" : MslCore.hexByte(result.status)).append(",")
               .append(csv(result.note)).append("\n");
        }

        out.append("result,")
           .append(csv(config.cardLabel)).append(",")
           .append(csv(job)).append(",")
           .append(csv(MslCore.hex(config.targetTar))).append(",")
           .append(probes.size()).append(",,,")
           .append(csv(verdict)).append(",,")
           .append(csv(headline.length() == 0 ? detail : headline)).append("\n");

        return out.toString();
    }

    // ------------------------------------------------------------------
    // HTML - the one a person reads
    // ------------------------------------------------------------------

    public String toHtml()
    {
        StringBuilder out = new StringBuilder();
        out.append("<!DOCTYPE html>\n<html><head><meta charset=\"utf-8\">\n");
        out.append("<title>MSL run - ").append(html(config.cardLabel)).append("</title>\n");
        out.append("<style>\n").append(css()).append("</style>\n</head>\n<body>\n");

        out.append("<h1>Minimum Security Level &mdash; ").append(html(job)).append("</h1>\n");
        out.append("<p class=\"sub\">").append(html(config.cardLabel));
        if (config.operator != null && config.operator.trim().length() > 0)
        {
            out.append(" &middot; ").append(html(config.operator));
        }
        out.append(" &middot; ").append(html(startedAt)).append("</p>\n");

        out.append("<div class=\"verdict ").append(cssClass()).append("\">");
        out.append("<div class=\"tag\">").append(html(verdict)).append("</div>");
        out.append("<div><strong>").append(html(headline)).append("</strong>");
        if (detail.length() > 0)
        {
            out.append("<div class=\"detail\">").append(html(detail)).append("</div>");
        }
        out.append("</div></div>\n");

        out.append("<h2>Run</h2>\n<pre class=\"cfg\">")
           .append(html(config.describeForCertificate()))
           .append("</pre>\n");
        out.append("<p class=\"fine\">No key material appears in this report. Credentials are "
                   + "typed into the run dialog and are never written to a file.</p>\n");

        if (!installLines.isEmpty())
        {
            out.append("<h2>Install parameters</h2>\n<pre class=\"dump\">");
            for (int i = 0; i < installLines.size(); i++)
            {
                out.append(html(String.valueOf(installLines.get(i)))).append("\n");
            }
            out.append("</pre>\n");
        }

        if (!probes.isEmpty())
        {
            out.append("<h2>Probes</h2>\n<table>\n");
            out.append("<tr><th>#</th><th>SPI1</th><th>Security applied</th>"
                       + "<th>Outcome</th><th>PoR</th><th>What it means</th></tr>\n");

            for (int i = 0; i < probes.size(); i++)
            {
                MslProbing.Result result = (MslProbing.Result) probes.get(i);
                out.append("<tr class=\"").append(outcomeClass(result.outcome)).append("\">");
                out.append("<td>").append(i + 1).append("</td>");
                out.append("<td class=\"hex\">")
                   .append(MslCore.hexByte(result.probe.spiFirstOctet())).append("</td>");
                out.append("<td>").append(html(security(result.probe))).append("</td>");
                out.append("<td><span class=\"chip\">").append(html(result.outcome))
                   .append("</span></td>");
                out.append("<td class=\"hex\">")
                   .append(result.status < 0 ? "&mdash;" : MslCore.hexByte(result.status))
                   .append("</td>");
                out.append("<td>").append(html(result.note)).append("</td>");
                out.append("</tr>\n");
            }
            out.append("</table>\n");
        }

        if (!notes.isEmpty())
        {
            out.append("<h2>Notes</h2>\n<ul>\n");
            for (int i = 0; i < notes.size(); i++)
            {
                out.append("<li>").append(html(String.valueOf(notes.get(i)))).append("</li>\n");
            }
            out.append("</ul>\n");
        }

        out.append("<h2>What this does and does not prove</h2>\n<ul class=\"fine\">\n");
        out.append("<li>Response status <code>0A</code> is the only evidence of a Minimum "
                   + "Security Level. Nothing on a card reads install parameters back, so "
                   + "behaviour is the whole of the case.</li>\n");
        out.append("<li>A packet answered <code>01</code> (integrity) or <code>02</code>/"
                   + "<code>03</code> (counter) got <em>past</em> the security gate and counts "
                   + "as accepted here. A wrong key therefore cannot turn into a wrong MSL.</li>\n");
        out.append("<li>A probe with no PoR is INCONCLUSIVE, never a rejection. Reading silence "
                   + "as <code>0A</code> would push a threshold one notch too high.</li>\n");
        out.append("<li>The toolkit parameter field order is this tool's reading of ETSI "
                   + "TS 102 226 clause 8.2.1.3.2. Check the dump above against the spec before "
                   + "trusting an install on a card that matters.</li>\n");
        out.append("</ul>\n");

        out.append("<p class=\"fine\">MSL checking &mdash; UL Mobile Card Test Platform 3.8.0"
                   + "</p>\n</body></html>\n");
        return out.toString();
    }

    // ------------------------------------------------------------------
    // Writing
    // ------------------------------------------------------------------

    /**
     * Writes both files into the folder and returns the HTML one.
     *
     * The name carries the card label and the timestamp, so two runs on two
     * cards cannot overwrite each other - which is the whole reason a report
     * folder is worth having rather than one fixed file.
     */
    public File writeTo(String folder) throws IOException
    {
        File directory = new File(folder);
        if (!directory.isDirectory())
        {
            throw new IOException("not a folder: " + directory.getAbsolutePath());
        }

        String stamp = new SimpleDateFormat("yyyyMMdd-HHmmss").format(new Date());
        String base = "msl-" + job + "-" + safe(config.cardLabel) + "-" + stamp;

        File html = new File(directory, base + ".html");
        write(html, toHtml());
        write(new File(directory, base + ".csv"), toCsv());
        return html;
    }

    private static void write(File file, String text) throws IOException
    {
        Writer writer = new OutputStreamWriter(new FileOutputStream(file), "UTF-8");
        try
        {
            writer.write(text);
        }
        finally
        {
            writer.close();
        }
    }

    static String safe(String text)
    {
        if (text == null) { return "card"; }

        StringBuilder out = new StringBuilder();
        for (int i = 0; i < text.length(); i++)
        {
            char ch = text.charAt(i);
            boolean ok = (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z')
                || (ch >= '0' && ch <= '9') || ch == '-' || ch == '_';
            out.append(ok ? ch : '-');
        }
        String result = out.toString();
        return result.length() == 0 ? "card" : result;
    }

    // ------------------------------------------------------------------

    private static String security(MslProbing.Probe probe)
    {
        return MslCore.axisValueName(MslCore.AXIS_INTEGRITY, probe.integrity) + ", "
             + MslCore.axisValueName(MslCore.AXIS_CIPHER, probe.cipher) + ", "
             + MslCore.axisValueName(MslCore.AXIS_COUNTER, probe.counter);
    }

    private String cssClass()
    {
        if (PASS.equals(verdict))        { return "good"; }
        if (FAIL.equals(verdict))        { return "bad"; }
        return "warn";
    }

    private static String outcomeClass(String outcome)
    {
        if (MslProbing.ACCEPTED.equals(outcome))  { return "accepted"; }
        if (MslProbing.BELOW_MSL.equals(outcome)) { return "below"; }
        return "unclear";
    }

    private static String csv(String text)
    {
        if (text == null) { return ""; }

        String cleaned = text.replace('\n', ' ').replace('\r', ' ');
        if (cleaned.indexOf(',') < 0 && cleaned.indexOf('"') < 0) { return cleaned; }

        return "\"" + cleaned.replace("\"", "\"\"") + "\"";
    }

    static String html(String text)
    {
        if (text == null) { return ""; }

        StringBuilder out = new StringBuilder();
        for (int i = 0; i < text.length(); i++)
        {
            char ch = text.charAt(i);
            if (ch == '<')      { out.append("&lt;"); }
            else if (ch == '>') { out.append("&gt;"); }
            else if (ch == '&') { out.append("&amp;"); }
            else if (ch == '"') { out.append("&quot;"); }
            else                { out.append(ch); }
        }
        return out.toString();
    }

    private static String css()
    {
        return "body{font:14px/1.55 'Segoe UI',system-ui,sans-serif;color:#101828;"
             + "background:#f6f7f9;margin:0;padding:28px 32px;}"
             + "h1{font-size:20px;margin:0 0 2px;}"
             + "h2{font-size:14px;text-transform:uppercase;letter-spacing:.04em;color:#475467;"
             + "margin:26px 0 8px;}"
             + ".sub{color:#667085;margin:0 0 18px;}"
             + ".verdict{display:flex;gap:14px;align-items:center;padding:14px 16px;"
             + "border-radius:10px;border:1px solid #e4e7ec;background:#fff;}"
             + ".verdict .tag{font:700 13px/1 'Cascadia Mono',Consolas,monospace;padding:8px 12px;"
             + "border-radius:8px;color:#fff;}"
             + ".verdict .detail{color:#475467;font-size:13px;margin-top:3px;}"
             + ".verdict.good{background:#ecfdf3;border-color:#abefc6;}"
             + ".verdict.good .tag{background:#067647;}"
             + ".verdict.bad{background:#fef3f2;border-color:#fecdca;}"
             + ".verdict.bad .tag{background:#b42318;}"
             + ".verdict.warn{background:#fffaeb;border-color:#fedf89;}"
             + ".verdict.warn .tag{background:#b54708;}"
             + "table{border-collapse:collapse;width:100%;background:#fff;border:1px solid #e4e7ec;"
             + "border-radius:10px;overflow:hidden;font-size:13px;}"
             + "th{text-align:left;background:#f9fafb;color:#475467;font-size:11px;"
             + "text-transform:uppercase;letter-spacing:.04em;padding:9px 12px;"
             + "border-bottom:1px solid #e4e7ec;}"
             + "td{padding:9px 12px;border-bottom:1px solid #f2f4f7;vertical-align:top;}"
             + "tr:last-child td{border-bottom:0;}"
             + ".hex{font-family:'Cascadia Mono',Consolas,monospace;}"
             + ".chip{display:inline-block;padding:2px 8px;border-radius:999px;font-size:11px;"
             + "font-weight:600;}"
             + ".accepted .chip{background:#ecfdf3;color:#067647;}"
             + ".below .chip{background:#fef3f2;color:#b42318;}"
             + ".unclear .chip{background:#fffaeb;color:#b54708;}"
             + "pre{background:#fff;border:1px solid #e4e7ec;border-radius:10px;padding:12px 14px;"
             + "font:12px/1.6 'Cascadia Mono',Consolas,monospace;white-space:pre-wrap;}"
             + "code{font-family:'Cascadia Mono',Consolas,monospace;background:#f2f4f7;"
             + "padding:1px 5px;border-radius:4px;}"
             + ".fine{color:#667085;font-size:12.5px;}"
             + "ul{margin:6px 0 0 18px;padding:0;}li{margin-bottom:5px;}";
    }
}
