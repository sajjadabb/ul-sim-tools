"""
Card-free checks over the window's backend, msl_ui.Api.

No display is needed and none is opened: the whole point of keeping layout in
ui/index.html and rules in msl_ui.py is that the rules can be tested as plain
Python. What is covered here is what the window is actually responsible for -
refusing a run that must not start, turning a probe result into a table row, and
draining its own queues exactly once.

    python tools/selftest_ui.py
"""
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import mslcore as m
import msl_ui

PASSED = []
FAILED = []


def check(description, condition, detail=""):
    (PASSED if condition else FAILED).append(description)
    print(("ok    " if condition else "FAIL  ") + description
          + (("  -- " + str(detail)) if (detail and not condition) else ""))


def probe_form(**overrides):
    form = {"job": "discover", "reader": "", "tar": "B00010", "kvn": "01", "alg": "3des2",
            "key": "40" * 16, "counter": "1218", "spi2": "09", "profile": "02",
            "send_profile": True, "budget": "24", "allow_ciphering": False,
            "allow_one_higher": False, "claimed": "", "msl": "12", "grant_tar": "",
            "priority": "01", "timers": "00", "channels": "00"}
    form.update(overrides)
    return form


def complains(api, form, fragment):
    return any(fragment.lower() in p.lower() for p in api.problems(form))


api = msl_ui.Api()

# ---------------------------------------------------------------------------
# The live MSL readout
# ---------------------------------------------------------------------------

answer = api.decode_msl("12")
check("a valid MSL byte decodes to its three axes",
      answer["ok"] and "cryptographic checksum" in answer["text"], answer)
check("the decode names the counter policy too",
      "counter must be higher" in api.decode_msl("12")["text"])
check("an empty field decodes to nothing rather than an error",
      api.decode_msl("")["ok"] is False and api.decode_msl("")["text"] == "")
check("an MSL byte with reserved bits set is reported, not silently re-encoded",
      "reserved" in api.decode_msl("F2")["text"].lower(), api.decode_msl("F2"))
check("a non-hex MSL is reported rather than raising", api.decode_msl("zz")["ok"] is False)

# ---------------------------------------------------------------------------
# The gates. Nothing reaches a card until every one of these passes.
# ---------------------------------------------------------------------------

check("a complete discover form starts", api.problems(probe_form()) == [],
      api.problems(probe_form()))
check("a complete verify form starts",
      api.problems(probe_form(job="verify", claimed="12")) == [],
      api.problems(probe_form(job="verify", claimed="12")))
check("a complete params form starts",
      api.problems({"job": "params", "msl": "12", "grant_tar": "B00010"}) == [])

check("params without an MSL is refused",
      complains(api, {"job": "params", "msl": "", "grant_tar": "B00010"}, "MSL byte"))
check("params without a TAR is refused - an applet with no TAR can never be probed",
      complains(api, {"job": "params", "msl": "12", "grant_tar": ""}, "at least one TAR"))

check("a TAR that is not 3 bytes is refused",
      complains(api, probe_form(tar="B000"), "exactly 3 bytes"))
check("probing without a key is refused", complains(api, probe_form(key=""), "key is required"))
check("a missing counter is refused, with the reason spelled out",
      complains(api, probe_form(counter=""), "no PoR comes back"))
check("an SPI octet 2 asking for no PoR is refused",
      complains(api, probe_form(spi2="00"), "no PoR"))
check("an SPI octet 2 asking for a ciphered PoR is refused",
      complains(api, probe_form(spi2="19"), "ciphered PoR"))
check("a non-hex SPI octet 2 is refused rather than raising",
      complains(api, probe_form(spi2="zz"), "not hex"))
check("verify without a claimed MSL is refused",
      complains(api, probe_form(job="verify", claimed=""), "supposed to have"))
check("a probe budget too small to finish a walk is refused",
      complains(api, probe_form(budget="3"), "below 4"))
check("a non-numeric probe budget is refused rather than raising",
      complains(api, probe_form(budget="lots"), "not a number"))
check("ciphered probes without a key are refused",
      complains(api, probe_form(key="", allow_ciphering=True), "KIc"))

# A refused run must not start a thread or touch the card.
started = api.start(probe_form(tar=""))
check("start() refuses a bad form and reports every reason",
      started["ok"] is False and len(started["problems"]) >= 1, started)
check("a refused run leaves nothing running", api.running is False)

# ---------------------------------------------------------------------------
# Turning probe results into table rows
# ---------------------------------------------------------------------------

probe = m.Probe(m.INTEGRITY_CC, m.CIPHER_OFF, m.COUNTER_HIGHER)
api._row(m.ProbeResult(probe, "ACCEPTED", 0x00, ""))
api._row(m.ProbeResult(probe, "BELOW_MSL", 0x0A, "insufficient security level"))
api._row(m.ProbeResult(probe, "INCONCLUSIVE", None, "no PoR"))
update = api.poll()
rows = update["rows"]

check("every probe becomes a row", len(rows) == 3, len(rows))
check("the row carries the SPI first octet the probe was built with",
      rows[0]["spi"] == "%02X" % probe.spi_first_octet(), rows[0]["spi"])
check("the row spells out the security that was applied",
      "cryptographic checksum" in rows[0]["security"], rows[0]["security"])
check("outcomes map to distinct chip styles",
      [r["tag"] for r in rows] == ["accepted", "below", "unclear"],
      [r["tag"] for r in rows])
check("a probe with no PoR shows -- rather than a made-up status",
      rows[2]["status"] == "--", rows[2]["status"])
check("polling drains: the same rows are never delivered twice",
      api.poll()["rows"] == [])

# ---------------------------------------------------------------------------
# The offline job, end to end through the same entry point the window uses
# ---------------------------------------------------------------------------

started = api.start({"job": "params", "msl": "12", "grant_tar": "B00010, B00011",
                     "priority": "01", "timers": "00", "channels": "00"})
check("a good params form starts", started["ok"] is True, started)

deadline = time.time() + 5
while api.running and time.time() < deadline:
    time.sleep(0.02)
check("the run finishes and clears its own running flag", api.running is False)

update = api.poll()
text = "\n".join(line[0] for line in update["lines"])
check("the run produced the install parameters",
      "install parameters:" in text and "B00010" in text and "B00011" in text, text[:200])
check("the dump spells out the MSL rather than only the hex",
      "MINIMUM SECURITY LEVEL" in text.upper(), text[:300])
check("the dump names the clause to read it against", "102 226" in text)
check("it points at the UL script for the actual install", "MslScript" in text)

verdict = update["verdict"]
check("a finished run leaves a verdict", verdict is not None)
check("the verdict is the good state", verdict and verdict["state"] == "good", verdict)
check("the verdict carries the MSL byte that was encoded",
      verdict and verdict["byte"] == "12", verdict)
check("the verdict is drained too, so it is not reapplied on the next poll",
      api.poll()["verdict"] is None)

# ---------------------------------------------------------------------------

print()
print("%d passed, %d failed" % (len(PASSED), len(FAILED)))
sys.exit(1 if FAILED else 0)
