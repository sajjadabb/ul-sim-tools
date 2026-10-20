"""
MSL Checker - the window.

A native window rendering ui/index.html through the system WebView (Edge
WebView2 on Windows), with this file as its backend. The interface is HTML and
CSS because that is what the other GUI tools in this repository are, and because
a real stylesheet gets a readable table and a legible verdict far more directly
than a widget toolkit does.

    python tools/msl_ui.py

The split is deliberate and worth keeping: index.html holds no knowledge of MSL,
and this file holds no knowledge of layout. Everything the window shows comes
from mslcore.py and msl_tool.py - the same code the CLI runs and the self-tests
cover - so the window cannot drift away from the engine. The Api class below is
plain Python with no webview import in its methods, which is what lets
selftest_ui.py exercise every rule in it without opening a window at all.

Two things it deliberately does NOT do:

  * install to a card. Setting an MSL means INSTALL inside a GlobalPlatform
    secure channel, and the trustworthy path for that is MslScript's install job on
    UL platform, where SCP02 is the SDK's job rather than hand-rolled. This
    window builds and explains the install parameters so they can be reviewed
    before that run, which is the part that actually needs checking.

  * remember your key. It lives in one field, is passed straight to the packet
    builder, and is never written anywhere.
"""
import os
import sys
import threading
import traceback

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import mslcore as m

# Under PyInstaller the interface is unpacked beside the frozen script rather
# than next to this source file, so _MEIPASS is the base when it exists.
BASE = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
PAGE = os.path.join(BASE, "ui", "index.html")

OUTCOME_TAG = {"ACCEPTED": "accepted", "BELOW_MSL": "below", "INCONCLUSIVE": "unclear"}


class TappedSender(object):
    """
    Wraps the real sender so every probe result reaches the table as it happens.

    The probing code stays unaware of any of this: it asks a callable for a
    result and gets one. Putting the tap here rather than inside OtaProbeSender
    keeps the engine identical to the one the CLI and the self-tests run.
    """

    def __init__(self, inner, on_result):
        self.inner = inner
        self.on_result = on_result

    def __call__(self, probe):
        result = self.inner(probe)
        self.on_result(result)
        return result

    def __getattr__(self, name):
        return getattr(self.inner, name)


class Job(object):
    """The values one run needs, in the shape msl_tool's helpers already take."""

    def __init__(self, **values):
        self.__dict__.update(values)


class Api(object):
    """
    Everything the page can call. No webview import, no widgets, no layout -
    which is exactly why the whole of it is testable without a display.
    """

    def __init__(self):
        self.lock = threading.Lock()
        self.lines = []
        self.rows = []
        self.verdict = None
        self.running = False
        self.last_params = ""

    # -- what the page polls ------------------------------------------------

    def poll(self):
        with self.lock:
            lines, self.lines = self.lines, []
            rows, self.rows = self.rows, []
            verdict, self.verdict = self.verdict, None
            running = self.running
        return {"lines": lines, "rows": rows, "verdict": verdict, "running": running}

    def say(self, text, tag=None):
        with self.lock:
            self.lines.append([str(text), tag])

    def _row(self, result):
        probe = result.probe
        with self.lock:
            self.rows.append({
                "spi": "%02X" % probe.spi_first_octet(),
                "security": "%s, %s, %s" % (m.INTEGRITY_NAMES[probe.integrity],
                                            m.CIPHER_NAMES[probe.cipher],
                                            m.COUNTER_NAMES[probe.counter]),
                "outcome": result.outcome,
                "tag": OUTCOME_TAG.get(result.outcome, "unclear"),
                "status": "--" if result.status is None else "%02X" % result.status,
                "note": result.note or "",
            })

    def _verdict(self, state, byte, title, text):
        with self.lock:
            self.verdict = {"state": state,
                            "byte": "" if byte is None else "%02X" % byte,
                            "title": title, "text": text}

    # -- small things the page asks for -------------------------------------

    def decode_msl(self, text):
        """Says what a typed MSL byte means, while it is being typed."""
        text = (text or "").strip()
        if not text:
            return {"ok": False, "text": ""}
        try:
            return {"ok": True, "text": m.MslLevel.from_byte(int(text, 16)).describe()}
        except ValueError as error:
            return {"ok": False, "text": str(error)}

    def list_readers(self):
        try:
            import msl_tool as t
            if t.readers is None:
                return {"error": "pyscard is not installed: pip install pyscard", "readers": []}
            return {"readers": [str(r) for r in t.readers()]}
        except Exception as error:
            return {"error": "could not list readers: %s" % error, "readers": []}

    # -- validation ---------------------------------------------------------

    def problems(self, form):
        """
        Every reason this run must not start, in the order they matter.

        Kept separate from start() so the rules can be tested one at a time, and
        so nothing reaches a card before all of them have been checked.
        """
        job = form.get("job")
        problems = []

        if job == "params":
            if not str(form.get("msl", "")).strip():
                problems.append("Give the MSL byte to encode.")
            if not str(form.get("grant_tar", "")).strip():
                problems.append("At least one TAR: without one the applet is not reachable over "
                                "OTA and its MSL can never be exercised.")
            return problems

        if len(str(form.get("tar", "")).strip()) != 6:
            problems.append("The applet TAR is exactly 3 bytes (6 hex digits).")
        if not str(form.get("key", "")).strip():
            problems.append("The KIc/KID key is required.")
        if not str(form.get("counter", "")).strip():
            problems.append("A start counter is required, and it must be ABOVE the card's stored "
                            "value - too low and no PoR comes back at all, which looks exactly "
                            "like a wrong key.")
        try:
            spi2 = int(str(form.get("spi2", "")).strip(), 16)
            if spi2 & 0x03 == 0:
                problems.append("SPI octet 2 asks for no PoR, so the run would produce nothing. "
                                "Use 09 unless the profile says otherwise.")
            if spi2 & 0x10:
                problems.append("SPI octet 2 asks for a ciphered PoR, which this tool does not "
                                "decipher. Clear bit b5.")
        except ValueError:
            problems.append("SPI octet 2 is not hex.")

        if job == "verify" and not str(form.get("claimed", "")).strip():
            problems.append("Verifying needs the MSL the applet is supposed to have. If you do "
                            "not know it, use Find the MSL instead.")
        try:
            if int(str(form.get("budget", "24")).strip() or "24") < 4:
                problems.append("A probe budget below 4 cannot complete even the shortest walk.")
        except ValueError:
            problems.append("The probe budget is not a number.")

        if form.get("allow_ciphering") and not str(form.get("key", "")).strip():
            problems.append("Ciphered probes need the KIc key.")
        return problems

    # -- running ------------------------------------------------------------

    def start(self, form):
        if self.running:
            return {"ok": False, "problems": ["a run is already going"]}

        problems = self.problems(form)
        if problems:
            return {"ok": False, "problems": problems}

        self.running = True
        thread = threading.Thread(target=self._run, args=(form,))
        thread.daemon = True
        thread.start()
        return {"ok": True, "problems": []}

    def _run(self, form):
        import msl_tool as t

        class Redirect(object):
            def __init__(self, api):
                self.api = api

            def write(self, text):
                for line in str(text).rstrip("\n").split("\n"):
                    if line.strip():
                        self.api.say(line)

            def flush(self):
                pass

        previous = sys.stdout
        sys.stdout = Redirect(self)
        reader = None
        try:
            if form.get("job") == "params":
                self._params(t, form)
            else:
                reader = self._probe(t, form)
        except SystemExit as stop:
            self.say(str(stop), "bad")
            self._verdict("bad", None, "Stopped", str(stop))
        except Exception as error:
            self.say("The run stopped on an unhandled error:", "bad")
            for line in traceback.format_exc().split("\n"):
                if line.strip():
                    self.say("  " + line, "bad")
            self._verdict("bad", None, "Error", str(error))
        finally:
            sys.stdout = previous
            if reader is not None:
                try:
                    reader.close()
                except Exception:
                    pass
            with self.lock:
                self.running = False

    def _params(self, t, form):
        tars = [m.unhex(part.strip()) for part in str(form.get("grant_tar", "")).split(",")
                if part.strip()]
        toolkit = m.ToolkitParameters(
            t.parse_msl(str(form.get("msl")).strip()), tars,
            priority=int(str(form.get("priority") or "01"), 16),
            max_timers=int(str(form.get("timers") or "00"), 16),
            max_channels=int(str(form.get("channels") or "00"), 16))
        params = m.build_install_parameters(toolkit)
        self.last_params = m.hexs(params)

        self.say("install parameters: " + self.last_params, "head")
        self.say("")
        for line in m.describe_install_parameters(params):
            self.say(line)
        self.say("")
        self.say("Read that against ETSI TS 102 226 clause 8.2.1.3.2 before the first install on "
                 "a card you care about: the field ORDER is this tool's reading of the clause.")
        self.say("To install it, run MslScript on the UL platform and pick the install job - "
                 "GlobalPlatform secure channel, and there the SDK provides it.")

        level = m.msl_of_install_parameters(params)
        self._verdict("good", None if level is None else level.to_byte(), "Parameters built",
                      self.last_params + " - install with MslScript, then prove it with "
                      "Check an MSL.")

    def _probe(self, t, form):
        job = Job(reader=str(form.get("reader") or "").strip() or None,
                  tar=str(form.get("tar")).strip(),
                  kvn=str(form.get("kvn") or "01").strip(),
                  alg=str(form.get("alg") or "3des2").strip(),
                  key=str(form.get("key")).strip(),
                  kic_key=str(form.get("kic_key") or "").strip(),
                  counter=str(form.get("counter")).strip(),
                  spi2=str(form.get("spi2") or "09").strip(),
                  profile=str(form.get("profile") or "").strip()
                          if form.get("send_profile") else "",
                  budget=int(str(form.get("budget") or "24")),
                  allow_ciphering=bool(form.get("allow_ciphering")),
                  allow_one_higher=bool(form.get("allow_one_higher")),
                  silent_drop=bool(form.get("silent_drop")))

        reader, sender = t.open_sender(job)
        sender.verbose = False                       # the table is the output now
        ceiling = t.build_ceiling(job, True)
        self.say("reachable ceiling: " + ceiling.describe())

        oracle = m.Oracle(TappedSender(sender, self._row), budget=job.budget,
                          silent_drop=job.silent_drop)
        try:
            if form.get("job") == "verify":
                claimed = t.parse_msl(str(form.get("claimed")).strip())
                self.say("claimed MSL: " + claimed.describe(), "head")
                result = m.verify_msl(oracle, claimed, ceiling)
                for line in result.describe():
                    self.say(line, "good" if result.passed else "bad")
                if result.passed:
                    self._verdict("good", claimed.to_byte(), "MSL confirmed",
                                  "Accepted at %s, and rejected 0A one notch below on every axis "
                                  "there was something below to try." % claimed.describe())
                else:
                    self._verdict("bad", claimed.to_byte(), "Not demonstrated",
                                  "The card does not demonstrably enforce this. Read the probe "
                                  "table: a packet weaker than the claim that was ACCEPTED means "
                                  "the applet is reachable below its stated level.")
            else:
                result = m.discover_msl(oracle, ceiling)
                for line in result.describe():
                    self.say(line, "good" if result.msl is not None else "bad")
                if result.msl is None:
                    self._verdict("warn", None, "Not determined",
                                  " ".join(result.notes) or "The probes did not pin down an MSL.")
                elif result.confirmed:
                    self._verdict("good", result.msl.to_byte(), "MSL found",
                                  result.msl.describe() + " - confirmed by check probes at the "
                                  "level and one notch below each axis.")
                else:
                    self._verdict("warn", result.msl.to_byte(), "Found, not confirmed",
                                  result.msl.describe() + " - the check probes disagreed, so this "
                                  "card is not enforcing the MSL field by field. Read the log.")
        except m.ProbeBudgetExhausted as stop:
            self.say("stopped: %s" % stop, "bad")
            self._verdict("warn", None, "Budget reached", str(stop))

        if sender.card_counter is not None:
            self.say("")
            self.say("The card's counter is now %010X. Start the next run above that."
                     % sender.card_counter)
        return reader


def main():
    try:
        import webview
    except ImportError:
        raise SystemExit("pywebview is not installed: pip install pywebview")

    if not os.path.isfile(PAGE):
        raise SystemExit("the interface is missing: %s" % PAGE)

    # Ask for a window that fits the display actually in front of the operator.
    # A fixed 1220x820 is fine until it meets a scaled display, where those are
    # logical pixels and the right-hand column ends up past the screen edge.
    # Measured, not assumed: webview.screens[0] and the width/height this call
    # takes are in the same units as GetWindowRect reports, so the arithmetic
    # below is a straight fraction of the desktop. (Checked by opening the
    # window and reading its rectangle back: asking for 1129 wide put the right
    # edge at 1178 on a 1536-wide desktop.) Left to itself the window opens at
    # an offset that can push its right-hand column off the edge, so it is
    # centred explicitly.
    width, height, x, y = 1220, 820, None, None
    try:
        screen = webview.screens[0]
        width = min(width, int(screen.width * 0.92))
        height = min(height, int(screen.height * 0.90))
        x = max(0, (screen.width - width) // 2)
        y = max(0, (screen.height - height) // 3)
    except Exception:
        pass

    window_args = {"js_api": Api(), "width": width, "height": height,
                   "min_size": (940, 620)}
    if x is not None:
        window_args["x"], window_args["y"] = x, y

    webview.create_window("MSL Checker", PAGE, **window_args)
    webview.start()
    return 0


if __name__ == "__main__":
    sys.exit(main())
