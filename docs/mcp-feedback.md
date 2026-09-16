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
[archive/mcp-feedback.md](archive/mcp-feedback.md) (63 entries, several since verified live): the `set_function_signature`
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

## 2026-09-15 — batch — a mid-batch rename breaks later edits that use the old name
_Reported by the `hp-z27k-g3` session (GLHub.dll RE). Implemented as 0.17.1, pending deploy._

- **Task:** a natural rename-then-annotate plan: `{op:rename, function:"FUN_00464980",
  new_name:"X"}` followed by `{op:set_comment, function:"FUN_00464980", …}` in one batch.
- **Friction:** the later edits fail with "No function named or containing address
  'FUN_00464980'" — the rename already happened, so the old name no longer resolves. Every
  later edit had to use addresses.
- **Resolution (0.17.1):** batch resolves every edit's `function`/`location` NAME to an address
  against the pre-batch state, before any edit runs — the state the edit list was written from.
  Strings already in address syntax are untouched, and a name that doesn't resolve yet is left
  for its edit (it may reference something an earlier edit in the same batch creates). The same
  hazard when chaining STANDALONE calls quickly is inherent (each call resolves against current
  state) and is not changed — use the new name or the address there.

## 2026-09-15 — set_function_signature — unresolved-type errors name only the first type
_Reported by the `hp-z27k-g3` session. Error listing implemented as 0.17.1, pending deploy; the
auto-create-opaque-struct part declined — the forward-declaration workaround covers it in one
round trip._

- **Task:** apply a C signature mentioning not-yet-defined types (e.g. `std_string *`).
- **Friction:** "Can't resolve datatype" fails fast on the first unknown type, so a signature
  with several costs one round trip each; also asked for auto-creating opaque structs.
- **Resolution (0.17.1):** on a resolve failure the tool re-parses with each failing type
  substituted, collecting ALL unresolved names into one error ("unresolved type(s): a, b, c"),
  so a single define_types call can create the lot. The error also teaches the opaque-type
  path — `define_types source='struct std_string;'` yields an empty struct usable behind a
  pointer (smoke-verified) — which is why silent auto-creation was declined: an explicit empty
  struct in the type manager beats one the tool invents as a side effect.

## 2026-09-16 — create — dispatch/pointer tables resolved by hand, plus three 8051 notes
_Reported by the `hp-z27k-g3` session from the GL3523 (Keil C51) dogfood — the first non-x86
exercise of the server. Item 2 implemented as 0.18.0, pending deploy; 1, 3, 4 answered with
today-paths._

- **Task (2, the accepted one):** Keil `?C?CCASE` inline switch tables and 16-bit USB
  request-dispatch pointer tables — each entry needed read_bytes, `create kind=function`, and
  `create kind=reference` by hand.
- **Resolution (0.18.0):** `create kind=functions_from_table` walks `count` entries at
  `address` (`entry_size` defaulting to the program's pointer size, `stride` for
  `<pointer, extra fields>` records, endianness from the language, `ref_type` default computed_call),
  wiring a reference from every slot and creating a function at every target; out-of-memory
  entries are listed, not fatal. `count` is deliberately explicit — a guessed terminator would
  walk past tables whose 0 is a valid address elsewhere. The CCASE-aware *analyzer* half
  belongs to the new `ghidra-plugin-keil8051` session (spun up 2026-09-16; spec handed over —
  banked-code memory model first, then the CCASE analyzer and vector seeding).
- **1 (8051 vector seeding): not added** — per-processor vector maps are analyzer/loader
  knowledge, not MCP-surface; today's path is one `batch` of `create kind=function` edits at
  base+0/0x3/0xB/… (four edits, one call). An analyzer for it is in the
  `ghidra-plugin-keil8051` spec.
- **3 (load-base scoring for raw images): not added** — a one-shot-per-image diagnostic, fine
  out-of-band; will revisit if it becomes a recurring step.
- **4 (Genesys SFR names): closed, existing tools cover it** — the reporter tested
  `rename kind=label address=SFR:0xc8 new_name=T2CON_test_rename` on the GL3523 image: the
  language-defined SFR symbol renamed (and renamed back) cleanly, and `inspect` shows the
  primary label. No tool change needed.

## 2026-09-16 — search_memory — no way to search a whole on-disk file
_Reported by `hp-z27k-g3` (MStar scaler, 1.26 MB 8051 flash). Implemented in 0.19.0, pending
deploy._

- **Friction:** the 8051 language's 16-bit code space can't hold the image, so answering "does
  `AA 55` occur anywhere in this file" meant importing the file a second time as raw
  x86:LE:32 purely so `search_memory` could see every offset.
- **Resolution (0.19.0):** `search_memory source=file` (kind=bytes|text) scans the program's
  on-disk file and returns file offsets — pasteable into `read_file` — each with the address(es)
  this program loaded it at, or "not loaded in this program". Multi-program/project-wide search
  not added: the file scan covers the stated case, since every module program points back at
  the same source file.

## 2026-09-16 — list — bogus functions over string tables read as real handlers
_Reported by `hp-z27k-g3` (PD/VDM command-name table at CODE:4c7f). Implemented in 0.19.0._

- **Resolution:** `list kind=functions` ends a line with `<-- TEXT: N% of the body is character
  data` when ≥85% of the (sampled) body is printable ASCII or NUL/tab/newline and printable
  bytes are at least half — `filter='TEXT:'` lists them. Bodies under 16 bytes are never
  tagged. A tag on the existing line, like HUSK, rather than a new parameter. The analyzer-side
  cause (auto-analysis disassembling string tables) is not this server's to fix.

## 2026-09-16 — import — loader-specific options can only be set in the GUI
_Reported by `ghidra-plugin-keil8051` (its `MStarModuleLoader`'s `Module offsets` / `Module
size`). Implemented in 0.19.0, pending deploy._

- **Friction:** a loader's own options (`Loader.getDefaultOptions`) had no MCP path, so the
  explicit-offsets import — needed for the USB-PD payload at 0x108000, which has no vector
  table — was GUI-only.
- **Resolution (0.19.0):** `import options={name-or-arg: value}`. Ghidra's `ProgramLoader`
  applies options only by command-line arg and merely logs a warning for one it doesn't know,
  so the tool resolves each key against the chosen load spec's default options first: a name
  the loader doesn't offer is refused with the loader's full option list (name, arg, default),
  and an option declared without an arg is refused with the reason (the loader must give it
  one). Smoke-verified with BinaryLoader's `Block Name`.
