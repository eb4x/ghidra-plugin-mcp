# ghidra-plugin-mcp — Dogfooding Feedback

The friction log for this MCP server, kept in the repo where the fixes land. The
viceroy RE project (`../viceroy`) dogfoods this server for all its Ghidra work:
**every agent doing Ghidra work there must log friction here** — in this file, not
in viceroy — and also mention it in its end-of-task report. When improving a tool,
read the open entries below first.

**Why this log exists.** The plugin is a deliberate reaction to
[bethington/ghidra-mcp#307](https://github.com/bethington/ghidra-mcp/issues/307):
that project ballooned to ~250–270 tools, and
[the research cited in-thread](https://github.com/bethington/ghidra-mcp/issues/307#issuecomment-4809412263)
shows tool-selection accuracy collapses as the catalog grows (RAG-MCP: 13.6%
unfiltered vs 43.1% with retrieval; LongFuncEval: 7–85% degradation) — "no magic
prompt will guide it into discovery." The thread also flags token-wasteful JSON
output as its own failure mode. Our counter-bet is a **small, orthogonal tool set**
(one tool per intention, `kind`/`op` enums, native extension, streamable HTTP).
The risk of small is *missing capabilities and awkward consolidation* — this log
is how we measure that risk instead of guessing.

Log an entry whenever you:

- **Miss a tool or capability** — especially the moment you reach for something
  *outside* the server (a raw `Bash` hexdump of VICEROY.EXE, the legacy python
  bridge, asking the user to click in the GUI, Script Manager) because no tool
  covered it.
- **Find a tool counter-intuitive** — above all its **arguments**: you guessed a
  parameter name/shape wrong on the first call, the `kind`/`op` value you expected
  didn't exist, an operand type (`function`/`location`/`address`) rejected what you
  passed, or the error message didn't tell you how to fix the call.
- **Get output that didn't fit the job** — missing fields you then had to fetch
  with extra calls, pagination that fought you, results too verbose for context.

Keep entries short and concrete; the exact failing call is the most valuable part.
Append new entries at the bottom.

## Entry template

```markdown
## YYYY-MM-DD — <tool or gap> — <one-line summary>
- **Task:** what you were trying to do
- **Friction:** what happened (include the exact tool call / arguments that failed
  or surprised you, and the error text if any)
- **Expected:** what you expected the tool/args to be, or which missing tool you
  wanted
- **Workaround:** what you did instead (external tool reached for, extra calls,
  gave up)
```

---

<!-- entries below, newest last -->

_Resolved friction is archived in
[archive/mcp-feedback.md](archive/mcp-feedback.md) (70 entries, several since verified live): the `set_function_signature`
custom per-param storage (register / register-pair / stack) + custom `return` storage,
the `decompile` coverage header,
`xrefs`/`calls` honest-zero caveats, the OVERLAY_24 analyzer root-cause, `read_log`, `xRam…` global
resolution, the bare-address rename hint, `inspect` Variables + thunk-status, `decompile dump_symbols`,
`clear kind=local_variable|label|function`, `manage_types op=rename_field`, `create kind=function
end_address`, namespaced-symbol resolution, the `set_function_signature` RETF hint, the bounded
deferring save + `save` tool, the create-kind=thunk experiment (removed), `create kind=label
namespace` + `decompile dump_jumptables` (jump-table overrides), `manage_files` folder ops, the
`manage_files` recursive-delete handle release, the `dump_jumptables` false NOT CONSUMED
(segmented addresses compared as strings), the settled stale-`DecompInterface` question
(the pool does **not** serve stale symbols), the scratch-program delete (busy-check ordering +
consumer-naming errors), `create`/`clear kind=reference`, `search_memory kind=instruction`,
the `GET /version` readiness + build-stamp probe (the startup-wait entry; its
wait-for-console-pattern residual belongs to eclipse-runner, not this repo), and all three
viceroy-workflow-doc gaps (wildcard search in overlays — measured, it works; the symbol dump —
met by `list user_only`, **script execution deliberately still not added**; and bulk doc
migration — the `migrate` tool), the `migrate` code-clobber incident (data must never overwrite an
instruction), and the "no undo" gap — which turned out to have **no undo to expose**: Ghidra
discards its undo history on every save and this server auto-saves every call, so revert is
snapshot-based (`manage_files op=copy`; `migrate` auto-backs-up), and the DS-globals
zero-xref entry — resolved in the fork's `RTLinkXrefAnalyzer`, not the plugin, exactly as
the entry predicted: a deref pass (READ/WRITE) plus an address-of immediate pass
(`RefType.DATA`), with the structural caveat that a base label no instruction ever
addresses (`g_savegame_head` 5370) legitimately stays at 0, the three husk-hunt entries
(0.5.0: `list kind=bookmarks`, `list kind=functions` body size + `min_body`/`max_body`,
`disassemble` announcing undefined/offcut starts), and the ERROR-bookmark channel those
exposed — 100% false positives on VICEROY until the fork's `RTLinkOverlayAnalyzer` swept
its own stale marks (540 → 2, both survivors real), and the from-range `xrefs` gap (0.6.0:
`xrefs` takes a `function` body or a `min_address`/`max_address` range with a `filter` on the
other endpoint, and `clear` is a `batch` op — ~1500 calls become two), the `migrate`
custom-storage regression (0.7.0: pinned register/stack storage is carried verbatim across DBs
instead of re-derived WRONG — fseek's `offset` restored to Stack[0x6], 55 of VICEROY's signatures
carried; any it can't reconstruct are named, never silently downgraded), and the thunk-gate
blindness in `calls`/`xrefs` (0.7.0: `calls kind=callers` resolves through thunk gates to the real
callers — draw_colony_sprite's 5 overlay callers via the 281f gate — and both tools annotate
thunks), the RTLink overlay-stub resolution (fixed in the fork-turned-extension's
`RTLinkOverlayAnalyzer`, not here: stubs are real Ghidra thunks now, so `inspect`/`calls` name the
overlay target and nothing depends on the `OVLSTUB_<NN>_<OFFS>` naming rule), and the stranded-project
gap (0.8.0: `manage_project op=open|close|list_recent`, plus `get_application_info` flagging an
`[UNREACHABLE]` locator and program tools naming "project storage unreachable" instead of a raw
`db.NNN.gbf` path), and the silently-guessed prototype (0.8.1: every `decompile` header says
`prototype guessed`/`committed`, and names the UNDECLARED INPUTS the decompiler read but could not
place — measured at 7 of a 12-function sample on VICEROY, so the normal state, not an edge case),
and the unbounded EDT wait (0.8.2: one `util/Edt` policy for reaching the Swing thread, so a modal
dialog can no longer hang every write tool indefinitely — verified by forcing the branch, which
also surfaced the "Unable to lock due to active transaction" cascade a timeout leaves behind), and
the uninitialized-block read (0.8.3: `read_bytes` tells "mapped nowhere" apart from "the image never
carried these bytes" and points at the run-time writer, `inspect` marks the block `[UNINITIALIZED]`,
and a short read is footed with how much of the request was met), and the un-splittable struct field
(0.9.0: `manage_types op=set_field` retypes whatever sits at a byte offset, with `freeze_layout=true`
to turn off the packing that `define_types` gives anything parsed from C — offsets preserved — and
output that names the undefined bytes a shrink leaves behind so a split can be finished), and the
raw-binary import gap (0.10.0: `import` takes `loader` — class name or display name — `processor`,
`cspec` and `base_address`, forwarded straight to Ghidra's loader machinery, and the no-load-spec
error says to pass them), and the four MSC-CRT bulk-naming requests (0.11.0: `fid_apply` reports
every function it named — address, old → new, score, library — and every match it declined with
why; `import` takes a directory or glob, expands container files (OMF `.LIB`, `ar`, zip) into one
program per member, and queues analysis with `analyze=true` on the shared `util/Analysis` worker;
`create kind=functions_at_labels` promotes every user/imported label in code to a function; and
`fid_build` breaks down its skips, per program with `detail=true`), the two follow-ups from the same
run (0.12.0: `fid_build` ingests only user/imported names unless `include_analysis_names=true`, with an
`exclude` regex either way — the overlay auto-names that got stamped onto SPHERE's CRT — and `create
kind=function` disassembles first on undecoded bytes instead of silently making a 1-byte husk, naming
a HUSK when one still results), and the four notes from the SPHERE/RETURN naming agents (0.12.1:
`rename kind=function` absorbs a same-named secondary label instead of refusing, `create` documents
that `end_address` cannot shrink a function — clear first — and announces a THUNK result plus any
function Ghidra created beside it, and `search_memory` frames segmented hits on the containing
block's segment, not the image base), and the last open tool gap — the invisible register context (0.13.0:
`inspect` reports every explicitly-asserted register value at the address with the range it
covers, so a DS assumption can be checked instead of inferred from a decompilation; writing
context stays analyzer-territory by design), and the unfindable comment (0.14.0: `list
kind=comments` lists/filters every comment by text, kind, or address prefix, with
min_address/max_address scoping — no more decompiling functions to grep their comments), and the
one-at-a-time in_* discovery (0.15.0: `list kind=undeclared_inputs` sweeps the decompiler over
every function in scope and lists the offenders with their prototype state, and the decompile
header now states the real hazard — a guessed prototype omits register args, a wrong committed
one mis-binds declared params to the wrong storage; it never reorders them), and the
comment-rename verdict's one residual cost (0.16.0: `full=true` on `list kind=comments` returns
untruncated texts, so a bulk rewrite needs no per-address inspect calls), and the sweep's two
reporting hazards (0.16.1: flag-bit reads are partitioned out and named as artifacts — flags-only
functions tagged, not dropped — and registers sort alphabetically so nobody infers argument order
from enumeration order again), and the first request from outside the mads chain — the
undeletable CodeBrowser-held program (0.17.0: `manage_files op=delete` closes the file in every
running tool first, automatically when clean, with `on_dirty=discard` when it holds unsaved
changes — and note an open tab counts as changed even untouched)._


## 2026-08-31 — analyzer-side — an auto-created string swallowed the last byte of a JMP
_Not an MCP-tool gap: logged here because the tools are how it was found and fixed, and the fix
belongs in an analyzer (probably the fork — flag to the ghidra-dailydriver session when someone
works this area)._

- **Task:** (mads session, VICEROY) clean Bad Instruction bookmarks after the games-wide naming
  passes.
- **What happened:** an analysis-time ASCII string at `210d:152b` had been defined one byte too
  early, swallowing the last byte of the preceding `JMP` and leaving a Bad Instruction bookmark
  where disassembly then started offcut.
- **Workaround (clean, three calls):** `clear` the string, `create kind=instructions` to
  re-disassemble the JMP, re-define the string at `152c`.
- **Open question:** which analyzer scavenged the byte (core ASCII strings vs. something the
  RTLink analyzers expose), and whether it can respect instruction boundaries / existing flow
  when picking a string start. No tool change proposed — `disassemble`'s offcut announcement and
  the ERROR-bookmark channel surfaced it exactly as designed.


## 2026-09-18 — disassemble — no linear sweep, so a whole-program listing can't be pulled for an external diff
_Not yet a feature request: `ghidra-plugin-aeon` says it will send one if it builds a second
processor module, and would rather the effort go to something the whole team hits. Logged now
because the design answer is fresh and the next processor module will want the same thing._

- **Task:** accept a new SLEIGH module (MStar AEON R2) by diffing Ghidra's disassembly of four
  firmware fixtures, ~1.16M instructions, against the vendor `aeon-elf-objdump` — the standard
  `dailydriver` set. Permitted by the vendor-oracle carve-out in CLAUDE.md.
- **Friction:** `disassemble` takes `function`, or `address` + `count` capped at 4096, and
  follows flow. A linear sweep visits bytes flow never reaches, so neither form produces the
  listing, and paging 1.16M instructions by address is not a real option. aeon wrote
  `ghidra_scripts/AeonDumpDisasm.java` instead (committed, re-runnable, in its repo).
- **Wanted (aeon's design, which I'd build as specified):** a linear-sweep mode on
  `disassemble` — `linear=true`, start + end address, a paging cursor — emitting one row per
  address visited: `address, length, mnemonic, operands`. On a decode failure, a one-byte
  undecodable row, then resync. **The resync is the part with no substitute:** two independent
  sweeps only stay comparable if both advance the same way past a bad byte. The rule, verbatim
  from aeon: *advance one byte and try again, and the row emitted for that byte reports length 1
  — the byte is consumed, not skipped.* Anything else (skipping to the next valid decode,
  advancing by a guessed length) desynchronises the two sweeps silently. aeon's
  `ghidra_scripts/AeonDumpDisasm.java` is the reference for the row format and carries a note
  saying so, so a change there comes to us as a message.
- **Explicitly NOT wanted: server-side comparison.** The oracle listing lives outside Ghidra and
  its shape varies per architecture (objdump here, IDA or a vendor tool next), so parsing
  arbitrary listings inside the server is a parser bug farm. More importantly the comparison
  carries the judgement — which `.word` rows are expected non-differences, that Ghidra zero-pads
  addresses (`0x00000927` vs `0x927`), that one length mismatch desynchronises everything after
  it so only the first difference is real — and that belongs in a committed script a reviewer
  can read, not in a shared server. Raw text out; the differ stays in the plugin repo.
- **Unit of difference:** length, mnemonic and operands classified separately, plus
  match/undecodable, reporting the first N of each class. **Length matters most:** a wrong length
  desynchronises the sweep, so a count of differing rows says nothing while the first differing
  address says everything.


## 2026-09-18 — MCPServerPlugin — a healthy instance logged "Failed to bind" as a WARN — eclipse-plugin-mcp
_Fixed in 0.20.1 (e821d18) and deployed, but **not yet confirmed live**; stays open until the
adopt path is observed. Archive it then._

- **Friction:** ~10s after a clean start, `application.log` carried
  `WARN (MCPServerPlugin) MCP server not started on 127.0.0.1:8765 (Failed to bind ...). Use
  Tools → MCPServer → Restart Server after freeing the port` — on an instance that was serving
  fine, with :8765 held by that very process (verified by pid). It is the line a session greps
  when a restart looks wrong, so it sent the reporter chasing a phantom stale instance, and its
  advice (free the port) was wrong: the holder was Ghidra itself.
- **Cause:** Ghidra instantiates the plugin once per tool that has it (the Front End, plus a
  restored CodeBrowser). `server` was an instance field, so the second instance always failed to
  bind the port the first held, and reported it as a failure.
- **Fix:** the server is process-wide (`SERVER_LOCK` / `sharedServer` / `owner`). A later
  instance adopts the running one and logs INFO naming the sharing tool; only the instance that
  bound the port stops it on `dispose`, so closing a tool no longer takes MCP down for the whole
  process; the WARN is reserved for a port held outside this process and its text now says so.
- **Verification status:** the 11:49 restart logged the listening line and no WARN — but no
  second instance initialised in that run, so the WARN's absence proves only that nothing
  regressed. MCP traffic alone does not create the second instance (eclipse-plugin-mcp tried via
  `get_program_info`); it appears to need a GUI action that opens a CodeBrowser tool. **What
  confirms the fix:** the `MCP server already running on ...; <tool> shares it` INFO appearing
  once a program is opened in the Ghidra window.


## 2026-09-18 — every program tool — a program needing a language upgrade failed with a bare exception name — ghidra-plugin-rtlink
_Fixed in 0.20.3, built and smoke-tested, but **not deployed**: :8765 still serves 0.20.2
(f2b74c0). Deploy on the next restart, then confirm the wording against a real stale program._

- **Friction:** the curated `/COLONIZE/VICEROY.EXE` in `mads` will not open in the current
  build — `Minor language change 4.7 -> 4.8`, the x86 SLEIGH spec having moved under the saved
  program. rtlink hit it while verifying something unrelated and imported a scratch copy
  instead. The wider problem it named: **every program saved under the older spec is in this
  state, and nothing reports it until something tries to open it.** hp-z27k-g3 has older
  8051/AEON-spec programs in `amplifi` in the same position.
- **Correction — my first account of this was wrong.** I wrote (and committed, f4de5fe) that
  the caller got a bare `ghidra.util.exception.VersionException` with no text. rtlink checked
  that against what it actually saw on 0.20.2 and it is false: both `disassemble` and `list`
  returned `Could not open program '/COLONIZE/VICEROY.EXE': Minor language change 4.7 -> 4.8`.
  Source confirms rtlink, not me — `LanguageVersionException.java:121` constructs
  `new LanguageVersionException("Minor language change " + fromVer + " -> " + toVer, true)`,
  the `String msg` constructor, so `getMessage()` is populated for every language-version case.
  I inferred the null-message path from `VersionException(boolean)` existing, without
  reproducing it. The lesson is the cheap one: rtlink's report said what it *did* (imported a
  scratch copy) and I filled in why from the API rather than asking what it saw.
- **What was actually wrong:** not the text, the advice. `Minor language change 4.7 -> 4.8` says
  the version moved; it does not say that an upgrade is one-way, that this server will not do
  it, or that the choice belongs to the program's owner. That is what 0.20.3 adds, and it is a
  smaller fix than the one I claimed to be making. `VersionException`'s other constructors do
  leave the message null, so reading `getDetailMessage()` as well is still right — just not the
  bug that was hit here.
- **Fix:** `openProgram` catches `VersionException` and reports what happened and who can act:
  upgradable (the common case) says the language or schema moved, that this server will not
  upgrade it because the rewrite is irreversible and auto-saved so it is the owner's call, and
  points at the GUI prompt or a fresh import; `NEWER_VERSION` says the instance itself is too
  old; non-upgradable says so plainly. `okToUpgrade` stays **false** deliberately.
- **Deliberately not built: an upgrade op.** Upgrading is exactly the irreversible,
  auto-saved, whole-program rewrite the no-undo rule exists for, and the programs that need it
  are hand-curated ones belonging to other sessions. A clear error that names the owner's
  choice beats a tool that makes it for them. Revisit only if a session asks for it explicitly.
- **Still open, but no longer hopeless — the pre-flight looks buildable.** I said `DomainFile`
  exposes no cheap staleness flag. It has no flag, but it does have the raw material, on
  rtlink's lead: `DomainFile.getMetadata()` returns the metadata persisted with the file, and
  `ProgramDB.getMetadata` (`ProgramDB.java:2413`) stores
  `"Language ID" -> languageID + " (" + languageVersion + "." + languageMinorVersion + ")"` —
  e.g. `x86:LE:16:Real Mode (4.7)`. **The stored version is right there**, so comparing it with
  what `LanguageService` reports for that language ID today answers "is this stale" for every
  file in a listing, without opening anything.
  **Unverified**: read from 12.1.3 source, not run. Whether the map is populated for a file
  this session has never opened is the thing to measure first — the whole idea rests on it. If
  it holds, `list_files` (and `get_program_info`) should mark stale programs, and *that* is the
  real fix; this entry stays open until then.
