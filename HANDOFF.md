# msl-checking — Project Handoff

Complete handoff for a new agent picking up this project. Read this fully before
touching code or the card. Written 2026-10-20.

---

## 1. What this project is

A tool to work with the **Minimum Security Level (MSL)** of UICC/SIM toolkit
applets, on the **UL Mobile Card Test Platform 3.8.0**. Three jobs plus OTA
applet loading:

1. **discover** — find the MSL an installed applet enforces (read-only).
2. **verify** — prove a claimed MSL is the one in force (read-only).
3. **install** — install a toolkit applet with a chosen MSL (ISD/SCP02, irreversible).
4. **ota-install** — load + install a CAP over OTA/RAM (Python AND UL/Java, irreversible).
5. **browse** — list applets and packages over OTA or SCP02 (read-only).
6. **delete** — remove an applet instance or a package (irreversible).

**MSL is write-only from outside the card** — no command reads install
parameters back. So the only way to know an applet's MSL is to send secured OTA
packets at different security levels and watch which are accepted vs rejected.
That inference is the heart of the tool.

Governing specs: ETSI TS 102 221/223/225/226, 3GPP TS 23.040, GlobalPlatform 2.x.

---

## 2. Where everything lives

- **Source (current):** `C:\Users\user\Projects\msl-checking`
  (It was previously at `C:\Users\user\Videos\TAR\msl-checking` and was MOVED. Any
  stale path references to Videos/TAR are wrong.)
- **UL output folder (compiled classes UL loads):**
  `C:\Users\user\OneDrive\Documents\TAR\Clases`
- **UL Class Path** (Tools → Options → Java) is set to that same folder.
- **UL SDK jar:** `C:\Program Files (x86)\UL Test Tools\UL Mobile Card Test Platform 3.8.0 [7]\lib\main\ul-scripttool.jar` (compiler: `tools.jar` beside it).
- **The operator's CAP / card docs:** `C:\Users\user\OneDrive\Desktop\develope new ssd\`
  (`MobilePaymentApplet.cap`, `MCI -14000213.xlsx`, `updated TAR List.xlsx`, release notes).

### Layout
```
lib/        shared by the UL scripts (compiled against the SDK)
  MslCore.java        MSL encoding, install-param TLVs (two formats), envelope + PoR, INSTALL
                      APDU, GET STATUS + DELETE APDUs, registry + RAM response parsing
  MslCapLoad.java     twin of capload.py: CAP -> load file -> INSTALL[for load] + LOAD chain
  MslProbing.java     the inference: Probe/Result/Oracle/discover/verify, SimulatedCard
  MslConfig.java      what a run needs + validation gates
  MslConfigDialog.java the run dialog (JFrame, tabs, dropdowns from SDK enums)
  MslProfile.java     non-secret prefill; refuses key-looking entries
  MslLog.java         live log window + verdict block
  MslReport.java      HTML + CSV report writer
  UlChoices.java      bridge: SDK enums <-> tool integers; packs SPI via the SDK's SPI ctor
scripts/
  MslScript.java      ONE script, all six jobs; job chosen in the dialog
selftest/
  MslSelfTest.java    404 card-free Java checks
tools/        normal mode (Python + pyscard), no UL licence
  mslcore.py          Python twin of MslCore + MslProbing (ports of each other)
  msl_tool.py         CLI: packet build, envelope, PoR parse, the jobs, ota-install
  capload.py          CAP -> GP Load File -> INSTALL[for load] + LOAD blocks + INSTALL[for install]
  msl_ui.py + ui/index.html  the HTML desktop app (pywebview); selftest_ui.py
  selftest_msl.py (411)  selftest_capload.py (26)
  selftest_ram.py (89)   end-to-end: browse/delete/ota-install against a simulated
                         card that unwraps the packets and answers like a card manager
app/        MSL Checker.exe (PyInstaller build of msl_ui.py)
docs/       UL-TEST-GUIDE-FA.md, USER_MANUAL_FA.html
reports/    generated run reports
```

### Build / deploy / test
```bash
# full offline gate (run after EVERY edit; the operator's CLAUDE.md requires it)
./selftest.sh          # Java 404, Python 411, UI 38, capload 26, RAM 89 — all must pass

# compile + deploy to the UL folder so UL picks up changes
OUT="C:/Users/user/OneDrive/Documents/TAR/Clases" ./build.sh lib/*.java scripts/*.java

# rebuild the standalone exe (after tools/ changes)
python -m PyInstaller --noconfirm app/"MSL Checker.spec"
```
After redeploying classes, **close UL completely and reopen** — the JVM caches a
loaded class for the whole session; re-running a script does NOT reload it.

---

## 3. The card under test (confirmed live)

- **Label "saga"** = MCI / Hamrah-e Aval SIM. ATR
  `3B 9F 96 80 1F 87 80 31 E0 73 FE 21 1B 67 4A 4C 75 30 31 13 59 A8`
  (historical bytes "JLu01" = the C2 Jav-JLu01.13 platform). Reader: **Identiv
  uTrust 4701 contact, T=0**.
- **OTA key (KVN 01, KIc=KID=KIK):** a 16-byte 3DES-2key value supplied at
  runtime by the operator. **Never stored anywhere; ask the operator for it each
  session; keep it out of every file, log and report.** The operator has ALL keys
  (OTA, ISD/SCP02, card manager).
- **This key also authenticates to the card manager (TAR 000000)** — GET STATUS
  over OTA returned PoR 00. So OTA card content management is reachable with it.
- **Per-applet MSL/TAR ground truth** (from the two profile xlsx, and 5 confirmed
  live): USIM `B00011`, ISIM `B00020`, HPSIM `B00021`, RFM `B00010`, EAP `B00022`
  all **MSL = 0x12** (CC, no ciphering, counter-higher). RAM `000000`.
- **S@T / HTTPS / CAT_TP** are documented MSL=00 but are **NOT OTA-reachable**
  with KVN01 (even the weakest no-integrity/no-counter packet drops). Likely a
  separate key set or STK-menu-only. So **no OTA-reachable MSL=0 hole on this
  card** — security posture sound.

### Three card behaviours that shaped the tool (critical to understand the logs)
1. **Silent drop instead of 0A.** A below-MSL (or bad-MAC, or counter-low) packet
   gets `ENVELOPE 6200`, NO PoR — not the spec's `0A`. Anti-oracle hardening. The
   tool's **silent-drop mode** re-labels a no-PoR drop as BELOW_MSL, but ONLY
   after a baseline probe returned a PoR (so a dead/wrong-key card is never
   misread). On this card the silent-drop checkbox MUST be ticked or discover
   reports "undetermined".
2. **PoR comes back via `61 xx` (T=0).** After ENVELOPE the card says `61 1B`
   ("27 bytes waiting"); you must **GET RESPONSE** to pull the PoR.
   `MslScript.Sender.read()` loops on `61xx` — this was found and fixed on the
   first live UL run.
3. **No PoR without a valid MAC.** The real key is required; a dummy key drops
   silently. (Differs from the earlier ECI card which answered 0A pre-MAC.)
4. **A RAM command script is case 3 APDUs — no Le, and T=0 rules apply inside
   it.** Two live findings, same run (2026-10-20): Confirmed live 2026-10-20:
   a GET STATUS sent as `80 F2 40 00 02 4F 00 00` came back PoR 00 with
   additional data `02 6F 00` — *two* commands executed from a script carrying
   one. The card read the trailing `00` as the start of a second, malformed
   command, and because the compact response format reports only the LAST
   command's status and data, the real GET STATUS answer was discarded. Drop
   the Le and the same command works. `MslCore.buildGetStatusApdu` and
   `buildDeleteApdu` now default to no-Le, the contact/SCP02 path asks for it
   explicitly, and `MslScript.browse` walks the four forms (Le × response
   format) until the card accepts one and then stays with it.
   **Read the command count in every PoR**: more commands than were sent is the
   card telling you an APDU carried bytes it read as another command.
   Then, with the Le dropped, the same GET STATUS answered **6159** (P1=40) and
   **6160** (P1=10) — 89 and 96 bytes of registry *waiting*. Inside a packet
   there is no transport layer to fetch them: the script must carry a
   `00 C0 00 00 xx` GET RESPONSE after the command, and since the compact
   response reports only the LAST command, that GET RESPONSE is what brings the
   registry back. `MslScript.readPendingData` re-sends the command with the
   GET RESPONSE appended, and retries once on 6C yy. **61 xx is not a refusal.**

---

## 4. Gotchas / traps (will waste a session if missed)

- **The counter field is HEX**, in both the CLI (`--counter`) and the dialog
  (Start counter). "600000" means 0x600000 ≈ 6.3M, not 600000. The CNTR is a
  5-byte value, zero-padded.
- **The counter must be ABOVE the card's current**, per (TAR, key set). Too low →
  silent drop (6200), looks exactly like a wrong key. This session's testing
  pushed `B00011`'s counter to ~0x3000000 and `000000`'s to ~0x4000000. The PoR
  echoes the accepted counter; start the next run above it.
- **Do NOT tick "Allow counter exactly one higher" for discover.** It makes the
  ceiling use the one-higher policy, which needs the counter to be *exactly*
  card+1 — unknown on the first probe → the ceiling drops → no baseline → UNKNOWN.
- **Tick "Card discards below-MSL packets silently"** (silent-drop) for this card.
- **KIc and KID are independent keys.** `MslConfig.otaKey` = KID (signs the MAC);
  `otaKicKey` = KIc (ciphering), falls back to KID when blank. In this key set all
  three are equal, but do not assume that. CLI: `--kid-key` / `--kic-key`, or
  `--key` for both.
- **Source files can revert on disk** (OneDrive sync / an open editor did it to
  `MslScript.java` once, silently losing an edit). After editing, re-grep the
  source for your change AND confirm the string is in the deployed `.class`
  before telling the operator to re-run.
- **The reader is held exclusively by UL.** pyscard gets SCARD_E_SHARING_VIOLATION
  while `ulcardtest-3.8.0.exe` is open. Close UL to run the Python path; the
  operator must run the UL path themselves (an agent cannot click the UL GUI).
- **Keys are never written to any file, including reports.** There are tests that
  assert this. Keep it that way.

---

## 5. What is verified vs not

| Thing | Status |
|---|---|
| Offline gate (964 checks) | ✅ all green |
| Python engine on live card (discover, 5 applets = MSL 12) | ✅ live |
| UL `MslScript` discover on live card (USIM B00011 = MSL 12, PASS) | ✅ live (after the 61xx fix) |
| silent-drop + KIc/KID split | ✅ live + tested |
| ota-install packet construction (dry run, real CAP) | ✅ built + 26 tests |
| Card manager reachable over OTA with the key (GET STATUS) | ✅ live PoR 00 — but see below: the PoR was 00 while the command itself answered 6F00, which earlier sessions did not check |
| browse in UL on the live card (packet accepted, inner SW read) | ⚠️ 2026-10-20: transport proven end to end (TERMINAL PROFILE 9000, PoR 00, counter echoed); GET STATUS answered 6F00 because of the Le byte — fixed, not yet re-run |
| **ota-install actually sending (irreversible)** | ❌ NOT run — awaiting operator go |
| ota-install / browse / delete ported to UL (Java) | ✅ built + 104 new offline checks; ❌ never compiled against the real SDK jar, never run in UL |
| Java CAP loader vs Python capload.py (same CAP, 3 block sizes) | ✅ byte-identical (differential harness) |
| browse / delete / ota-install end-to-end (Python, simulated card) | ✅ 68 checks: the real CLI, packet builder, envelope, 61xx reader and PoR parser against a card that verifies the load file SHA-1 itself |
| **ISD/SCP02 install** | ❌ never live-tested (no SCP02 keys entered yet) |
| Ciphered (0x16) sweep to prove the ciphering axis | ❌ not run (cipher axis still "untested") |

---

## 6. Pending work the operator asked for

Items 1-3 below were **done** in the session of 2026-10-20 (branch
`claude/lucid-pasteur-fe4gpm`); what is left of them is verification on the
operator's machine, which is the first thing to do.

1. ~~Port ota-install to UL/Java.~~ **Done.** `MslScript.otaInstall()` plus the
   new `lib/MslCapLoad.java`. The LOAD chain is built in Java because over OTA
   the block size has to be ours (~160 bytes, not the 255 a contact channel
   allows), and the safety the handoff asked for is kept a different way: the
   load file is cross-checked against the SDK's `LoadSequence` for the same CAP
   — same AID, same SHA-1 over the whole block — and nothing is sent if they
   disagree. Both the PoR status and the inner SW are checked per step.
2. ~~Browse capability.~~ **Done.** `MslScript.browse()`, GET STATUS P1 80 / 40
   / 10 over either road, following the card's 6310 continuations, with both
   response formats parsed (compact and the GP 2.2 E3 TLV one).
3. ~~Delete capability.~~ **Done.** `MslScript.deleteObject()`, P2 00 / 80,
   dry run by default, and it refuses to send when the registry does not hold
   the AID.
4. **Verify the three new jobs on the operator's machine**, in this order:
   `./build.sh lib/*.java scripts/*.java` (first real compile against the SDK
   jar — nothing in a cloud container can do that), `./selftest.sh`, then
   **browse** in UL, which is read-only and exercises the whole RAM path:
   TERMINAL PROFILE, packet, PoR, inner SW, registry parse. If browse lists the
   card, ota-install's transport is proven; only the CAP serialization and the
   INSTALL itself remain.
5. **Run the ota-install** (irreversible) on the operator's go, or on a test card.
6. **Ciphered 0x16 sweep** (enable "Allow ciphered probes", fill KIc) to measure
   the ciphering axis and remove the one "untested" axis from the reports.
7. **The HTML desktop app (`app/MSL Checker.exe`, `tools/msl_ui.py` +
   `ui/index.html`) still offers only discover / verify / params.** The three
   new jobs were added to the UL dialog and the Python CLI, not to it. Adding
   browse there would be the useful one (read-only, and it is what an operator
   reaches for first); ota-install and delete arguably belong behind the UL
   dialog's gates rather than in a one-click app.

### ota-install: how to actually send (when authorized)
```bash
# Dry run (default) builds all 7 packets, sends nothing:
python tools/msl_tool.py ota-install \
  --cap ".../MobilePaymentApplet.cap" \
  --module 112233445500 --instance 112233445500 \
  --tar 000000 --kvn 01 --alg 3des2 --key <KID> --counter 5000000
# Add --confirm to actually LOAD + INSTALL (IRREVERSIBLE). MobilePaymentApplet is
# a PLAIN applet (extends javacard.framework.Applet), so NO --msl/--grant-tar:
# it installs with empty C9 application parameters. ELF AID 1122334455,
# applet AID 112233445500 (parsed from the CAP).
```

---

## 7. Design invariants (do not break)

- `mslcore.py` and `MslCore.java` + `MslProbing.java` are **ports of each other**.
  A differential harness confirmed 386 install-parameter cases byte-identical.
  Change both together and keep them in step.
- **Classification rule:** PoR `01` (MAC), `02/03` (counter) mean the packet got
  PAST the MSL gate → scored ACCEPTED. Only `0A` (or a silent drop after a
  baseline) is BELOW_MSL. This is why a wrong key never becomes a wrong MSL.
  Confirmed against ETSI TS 102 226 §8.2.1.3.2.4.2 (per-axis `SPI1 >= MSLD`).
- **Two install-parameter formats** (TS 102 226): UICC = tag `EA` wrapping `80`;
  SIM = tag `EF` wrapping `CA`. `EA{CA}` is a malformed cross the card rejects
  with 6A80. Default is UICC; the dialog has a format dropdown.
- **SPI is packed by the SDK's typed `SPI` constructor** in the UL path
  (`UlChoices`), not hand-shifted; the self-test asserts it matches
  `MslCore.spiFirstOctet` for all 32 combinations.
- **Nothing is sent before the dialog is confirmed** — not even a reset. Cancel/
  close = send nothing.

---

## 8. Persisted memory (card facts survive across sessions)

These memory files hold the load-bearing facts; a new agent should read them:
- `mci-card-msl-tar-ground-truth` — per-applet MSL/TAR + the live results.
- `msl-checking-live-card-corrections` — KIc/KID split, silent-drop, no-PoR-without-MAC.
- `msl-checking-project` — the design and the (now-resolved) flagged unknowns.
- `ota-rfm-contact-interface` — TERMINAL PROFILE first, counter above card's, CAT CR bit.
- `mci-of-file-key-map`, `mci-usim-kvn-provisioning-confirmed-facts` — key schema.
- `ul-sdk-no-decompile` — never decompile UL `.class` files (EULA); ask for Javadoc.
- `audit-every-change-yourself` — run the full gate after every edit, report it.

---

## 9. Immediate next step

That request — **update UL: port ota-install to the Java/UL side, and add browse
+ delete of applets/packages** — is implemented (section 6, items 1-3), with
offline tests and a dry-run + confirm gate on both destructive jobs, and the
Python twin kept in step.

What is NOT done, and cannot be done away from the operator's machine: **none of
the new Java has been compiled against the real `ul-scripttool.jar`, and none of
it has run in UL or touched a card.** A cloud container has no SDK jar and no
reader. The offline evidence is: 376 Java checks (the dialog and the self-test
compile; `MslScript` was symbol-checked and introduces no SDK call that was not
already in the file), 383 + 38 + 22 Python checks, and a differential harness
proving the Java CAP loader and `capload.py` produce byte-identical load files,
LOAD chains, GET STATUS/DELETE APDUs and registry parses on the same CAP.

So the next step is item 6.4: build on the UL machine, run the gate, then run
**browse** — read-only, and it exercises the entire RAM path. Confirm with the
operator before any irreversible send, and prefer a disposable test card over
"saga".
