# MSL checking for applets

Install an applet with a specific **Minimum Security Level**, prove the MSL a
card is actually enforcing, and find that MSL when nobody knows it.

Built twice, on purpose:

| | normal mode | UL Mobile Card Test Platform |
|---|---|---|
| where | `tools/` | `lib/` + `scripts/` |
| language | Python + pyscard + pycryptodomex | Java 8, UL SDK 3.8.0 |
| needs | a PC/SC reader | the platform and its dongle |
| builds the packet | itself, from TS 102 225 | the SDK's `SecuredCommandPacketFactory` |
| input | command line | a modal run dialog, like the other UL tasks here |

Both sides run the **same algorithm** — `tools/mslcore.py` and
`lib/MslCore.java` + `lib/MslProbing.java` are ports of each other, class for
class — so an answer from one can be checked against the other, and the logic
can be tested without a card at all. The two self-tests share the same body of
checks; the Java side adds a few of its own for the parts that only exist there.

---

## What MSL is, and why the tool is shaped like this

An applet on a UICC carries a Minimum Security Level, fixed at install time
inside its install parameters (ETSI TS 102 226 clause 8.2.1.3.2). When a secured
packet arrives for that applet's TAR, the card compares the security the packet
actually applied — the SPI first octet — against the MSL, and rejects it with
**response status `0A`, insufficient security level**, *before* checking the MAC
or the counter.

Three consequences drive the whole design:

1. **`0A` is a clean signal.** No wrong key and no stale counter can produce it.
   That is what makes an MSL testable from outside at all.
2. **Everything else after the gate means the gate was passed.** A packet
   answered `01` (MAC failed) or `02` (counter low) got *past* the MSL check.
   Treating those as failures is the easiest way to get a confidently wrong
   answer out of this kind of probing, so `classify()` counts them as accepted
   and both self-tests have a regression for it.
3. **Nothing reads install parameters back off a card.** GET STATUS returns AID,
   life cycle and privileges; GET DATA has no tag for this. The MSL is
   write-only from the outside, so *behaviour is the only evidence there is* —
   probing is not a shortcut here, it is the only route.

The MSL byte is coded exactly like the SPI first octet:

```
b2 b1   integrity   00 none | 01 redundancy check | 10 cryptographic checksum | 11 digital signature
b3      ciphering   0 off | 1 on
b5 b4   counter     00 none | 01 present, not checked | 10 must be higher | 11 exactly one higher
```

so `12` = cryptographic checksum, no ciphering, counter must be higher — which
matches what the vendor spreadsheet for this card family documents for `0x12`,
the one independent check available for this encoding.

---

## The three jobs

### 1. Install an applet with a specific MSL

The MSL is a field in the INSTALL [for install and make selectable] parameters,
so "setting the MSL" means installing (or re-installing) the applet:

```
C9 <len> <application specific parameters>     GlobalPlatform, usually empty
EA <len> CA <len> <UICC toolkit parameters>    ETSI TS 102 226
                  priority, timers, menu entries, channels,
                  length of MSL field, MSL, length of TAR field, TAR(s)
```

- normal mode: `python tools/msl_tool.py params --msl 12 --grant-tar B00010` builds
  and explains the block without touching a card; `install` sends it, either as
  a printed APDU for your own GlobalPlatform tool (`--print-only`) or delivered
  to the card manager over RAM inside a secured packet (`--confirm`).
- UL: **`MslScript`**, job *install* (on `SCP02Script`) opens SCP02 to the ISD,
  optionally deletes a previous instance, optionally loads the CAP, sends
  INSTALL, and confirms in the registry that the instance is `SELECTABLE`.
  An applet installed but *not* selectable is unreachable by TAR — OTA answers
  `09`, not anything about security — so the script says so explicitly rather
  than reporting success.

### 2. Check that the MSL is set correctly

Two directions, because either alone proves nothing:

- a packet at **exactly** the claimed MSL must **not** be rejected `0A` — else
  the card wants more than was asked for;
- a packet **one notch weaker on each axis** must be rejected `0A` — else the
  card enforces *less* than was asked for. That is the finding that actually
  matters: an applet reachable at a lower security level than its profile
  claims.

An axis the claimed MSL leaves at its weakest value cannot be probed from below
and is reported as untested, never silently passed.

- normal mode: `msl_tool.py verify --tar B00010 --msl 12 ...`
- UL: `MslScript`, job *verify*.

### 3. Find the MSL of an installed applet

1. Probe the **ceiling** — the strongest packet the tooling can build. If that
   is rejected `0A`, the card's MSL is out of reach and no axis can be isolated:
   the run stops and says so instead of reporting "rejects everything".
2. For each axis, hold the other two at the ceiling and walk that axis upward.
   The first value not rejected `0A` is the card's minimum on it.
3. **Check the answer**: the inferred level must be accepted, and one notch
   below on each non-zero axis must come back `0A`.

Step 3 is what separates a measurement from a guess. A card enforcing the MSL on
only some axes, or comparing the byte as a whole rather than field by field,
fails step 3 and is reported **unconfirmed with the probe log** rather than
rounded into a tidy answer. Worst case is 12 probes; the common case is 5.

Silence is never read as rejection — a probe with no PoR is `INCONCLUSIVE` and
stops that axis's walk, because reading silence as `0A` pushes a threshold one
notch too high and produces exactly the confident wrong answer this tool exists
to avoid.

- normal mode: `msl_tool.py discover --tar B00010 ...`
- UL: `MslScript`, job *discover*.

---

## Running it

### Normal mode - the window

```
app/MSL Checker.exe
```

Double-clickable, nothing to install. Pick one of the three jobs, fill in the
card and key set, and watch the probes arrive a row at a time - each one showing
the SPI first octet it was built with, the security that applied, and whether the
card accepted it, rejected it `0A`, or said nothing usable. The verdict sits
above the table with the MSL byte in it. The MSL fields decode themselves as you
type, so `12` reads back as "cryptographic checksum, no ciphering, counter must
be higher" before anything is sent.
Rebuild it after changing anything under `tools/`:

```bash
python -m PyInstaller --noconfirm app/"MSL Checker.spec"
```

Or run it from source with `python tools/msl_app.py`.

The window deliberately does **not** install to a card. Setting an MSL means
INSTALL inside a GlobalPlatform secure channel, and the trustworthy path for
that is `MslScript`'s *install* job on the UL platform, where SCP02 is the SDK's
rather than hand-rolled. What the window does do is build and explain the
install parameters, which is the part that needs reviewing before that run.

### Normal mode - the command line

```bash
pip install pyscard pycryptodomex
python tools/selftest_msl.py                     # 286 checks, no card needed
python tools/msl_tool.py params --msl 12 --grant-tar B00010
python tools/msl_tool.py discover --tar B00010 --kvn 01 --key <hex> --counter 1218
```

Three preconditions for any OTA over a contact reader, two of which fail
silently:

1. **TERMINAL PROFILE first** (`80 10 00 00 01 02`). A plain PC/SC reader never
   sends one, so the card's toolkit stays dormant and every envelope is ignored.
2. **The counter must exceed the card's stored value**, or no PoR comes back at
   all. Every run prints where the card actually is, from the PoR echo.
3. **CAT TLV tags need the comprehension-required bit**: `82` device identities,
   `8B` SMS TPDU. Handled in `build_envelope`.

### UL platform

1. Tools → Options → Java: **Output Path** `build/`, and add `build/` to the
   **Class Path**. Same arrangement as `sim-os-atp`; if that already runs,
   nothing new is needed.
2. `./build.sh`, or compile `lib/*.java` first and the scripts after.
3. `./selftest.sh` — both self-tests, no card.
4. Run **`MslScript`** and pick a job on the first tab. Start with **discover**:
   it is read-only and tells you within a few packets whether the TAR, key set
   and counter are right, before any install is attempted.
5. Then **install** when you need to *set* an MSL, and **verify** to prove it
   took.

Both scripts show a run dialog before sending anything. Cancel means nothing is
sent — not even a reset. Credentials are typed fresh every run and are never
read from a file; `config/msl.properties` holds only non-secret pre-fill, and
entries that look like keys are dropped on load with a printed warning.

The MSL tab shows a **live, annotated dump of the exact install parameters that
will be sent**, byte by byte with the field each byte was assigned to. Since
nothing reads install parameters back off a card, that preview is the only
chance to catch a wrong block — read it before pressing Start.

---

## Two things this tool is honest about

**The toolkit field order is unverified against the spec text.** There is no
copy of ETSI TS 102 226 on this machine. The field order in `MslCore` /
`mslcore.py` is a careful reading of clause 8.2.1.3.2, and the MSL *byte* itself
is corroborated by the vendor spreadsheet's "0x12 = Counter Higher, CC, No
Ciphering" — but that corroborates the byte, not the fields around it. Hence the
annotated dump, and hence the raw-parameters escape hatch on both sides: paste a
field you have verified yourself and the builder is bypassed entirely. Read the
dump against your own copy of the spec before the first install on a card you
care about.

**`InstallForInstallAndMakeSelectableCommand.parameters(byte[])` has one
documented sentence and two readings.** The 3.8.0 Javadoc was read directly for
this - method summary and method detail both - and it says only "the install
parameters" with no further prose, so the ambiguity is confirmed rather than
assumed. This tool passes the whole install
parameters field (C9 then EA/CA) on the reading that "the install parameters"
means exactly that. If a card answers `6A80` to a block that reads correctly in
the preview, the other reading — that the SDK wraps what it is given — is what
to test next, and the dialog's *"build the INSTALL APDU here"* box does it: the
command is then built byte for byte by `MslCore` and sent through the same
secure channel. Nothing was decompiled to settle this; the Javadoc does not say,
so both routes are offered and the bytes actually sent are always printed.

---

## Layout

```
tools/      normal mode - runs on any PC/SC reader, no UL licence
  mslcore.py        the MSL logic: encoding, install parameters, inference. No I/O.
  msl_tool.py       the CLI: packet building, envelope, PoR parsing, the three jobs
  msl_app.py        the window - a Tkinter front end over the same two files
app/        MSL Checker.exe, built from msl_app.py with PyInstaller
  selftest_msl.py   286 card-free checks, including the packet builder's
                    length arithmetic (CPL, CHL, PCNTR padding)
  selftest_app.py   27 card-free checks over the window itself
lib/        shared by the UL scripts
  MslCore.java      Java port of mslcore.py's first half
  MslProbing.java   Java port of its second half - probes, discovery, verification
  MslConfig.java    what a run needs, and what stops it from starting
  MslConfigDialog.java  the run dialog - tabs, dropdowns, live validation
  UlChoices.java    the bridge to the SDK's own enums, and the SPI it packs
  MslProfile.java   non-secret pre-fill, with key material refused
  MslLog.java       live log window plus the platform's own output panel
scripts/
  MslScript.java    all three jobs, on SCP02Script - the job is a dropdown
selftest/
  MslSelfTest.java  248 card-free checks: the Python ones, plus the profile's
                    refusal to load key material, every MslConfig gate, and the
                    SDK enums against this tool's own integers
config/     optional non-secret pre-fill
build.sh    compiles outside the GUI
selftest.sh runs both self-tests
```

### The run dialog

Built to the same pattern as the ECI file-lifecycle dialog, because that pattern
earned it: tabs in scroll panes, a titled group per subject, the long reasoning
attached to the control it is about as a tooltip rather than printed beside it, a
live list of everything still wrong, and a Start button disabled until that list
is empty.

Every value drawn from a fixed set is a dropdown, and where the SDK already names
that set the dropdown is filled from **the SDK's own enum** — `IntegrityLevel`,
`CipherMode`, `CounterMode`, `PoRMode`, `PoRSMSType`, `SecurityLevel`. Nothing
types those names out, so a value that stops existing in a future SDK becomes a
compile error rather than a run that quietly does the wrong thing.

The MSL itself is **not typed as a hex byte**. It is chosen on the three axes it
is made of, and the byte is shown back as it is built:

```
Integrity:  CRYPTOGRAPHIC_CHECKSUM
Ciphering:  OFF
Counter:    PROCESS_IF_HIGHER
Builds MSL byte 12 - 12 (cryptographic checksum, no ciphering, counter must be higher)
```

Typing `1A` when `12` was meant is a one-character mistake that installs an applet
enforcing something nobody asked for, and no command reads it back afterwards to
catch it.

`UlChoices` is where the SDK's enums meet this tool's integers, so `MslCore` stays
free of SDK imports and remains checkable without the platform. The probe script
builds the SPI it actually sends through the SDK's typed `SPI` constructor rather
than shifting bits, and `MslSelfTest` asserts the two agree on octet 1 for all 32
combinations — a wrong SPI does not look like a wrong SPI, it looks like a card
that rejects everything.

### One script, three jobs

There used to be two scripts, because the two halves want different SDK base
classes: card content management is GlobalPlatform (`SCP02Script`), and the
SDK's ready-made OTA procedure lives on `ThreeGTerminalScript`. They cannot be
combined, so something had to give — and what gave is the envelope, not the
secure channel.

`MslScript` runs on `SCP02Script`. INSTALL keeps the SDK's proven SCP02
implementation; the probing half frames its own SMS-PP DOWNLOAD envelope around
a packet the SDK still builds (`SecuredCommandPacketFactory`) and reads the
answer back with `MslCore.buildEnvelope` / `parsePor` — ported from the Python
tool already proven against these cards, and covered byte for byte by the
self-test.

That is the right way round for the risk. A mistake in the install half changes
a card. A mistake in the envelope half produces no PoR and an `INCONCLUSIVE`
probe, which the inference already refuses to draw a conclusion from.

## Governing specs

- ETSI TS 102 225 — secured packet structure, SPI coding (clause 5.1.1)
- ETSI TS 102 226 — UICC toolkit application specific parameters, the MSL and
  response status `0A` (clause 8.2.1.3.2)
- ETSI TS 102 223 — SMS-PP DOWNLOAD envelope (clause 7.1.1)
- GlobalPlatform Card Specification 2.2 — INSTALL (clause 11.5), GET STATUS
- 3GPP TS 23.040 — the SMS-DELIVER TPDU the envelope carries
