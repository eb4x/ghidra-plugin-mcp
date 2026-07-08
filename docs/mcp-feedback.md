# ebbex-ghidra-mcp — Dogfooding Feedback

We are dogfooding our own MCP server plugin (`../ebbex-ghidra-mcp`) for all Ghidra
RE work on this project. **Every agent doing Ghidra work must log friction here**,
and also mention it in its end-of-task report.

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
[archive/mcp-feedback.md](archive/mcp-feedback.md) (12 entries as of 2026-07-08): the
`decompile` coverage header, `xrefs`/`calls` honest-zero caveats, the OVERLAY_24 analyzer
root-cause, `read_log`, `xRam…` global resolution, the bare-address rename hint, the
`inspect` Variables section, `decompile dump_symbols`, and `clear kind=local_variable`._

## 2026-07-08 — batch — "Unable to lock due to active transaction" yet the edits applied
- **Task:** Colony_Create annotation pass — two `batch` calls (49 and 13 edits) of
  renames/signatures/labels/comments.
- **Friction:** Both times `batch` threw
  `java.io.IOException: Unable to lock due to active transaction` — and both times
  the edits had actually been committed. The blind retry of the first batch then
  produced 16 spurious per-edit errors (`No function named ... 'OVL22_3744'`,
  `No parameter ... 'param_1'`) purely because the "failed" run had already
  applied those edits, which cost a diagnosis round-trip to realize no edit had
  been lost.
- **Expected:** Either atomic failure (nothing applied when the tool reports an
  exception) or a partial per-edit result list; never "error yet fully applied".
  Looks like the exception comes from a save/lock step *after* the transaction
  commits.
- **Workaround:** After any batch "failure", decompile a touched function to see
  what actually landed before retrying; treat rename retries as idempotent no-ops.

## 2026-07-08 — set_function_signature — wrong calling convention silently kept, args garble
- **Task:** Give the 281f far trampolines real prototypes so Colony_Create's call
  sites decompile with true arguments.
- **Friction:** `set_function_signature` applied 2-param prototypes cleanly but
  kept the functions' (wrong) near convention, so parameters mapped to
  `Stack[0x2]` instead of `Stack[0x4]` and every call site *still* showed a junk
  first argument — now eating one real arg, which is worse than before. No
  warning of the storage mismatch.
- **Expected:** A hint in the tool result when the applied params' storage
  conflicts with how call sites/`RETF` look, or docs noting that far functions
  frequently need an explicit `calling_convention`.
- **Workaround:** Re-applied every signature with
  `calling_convention="__cdecl16far"`; `decompile dump_symbols=true` was the tool
  that made the `Stack[0x2]` misplacement visible.

## 2026-07-08 — gap — no thunk create/repair for unresolved OVLSTUB stubs
- **Task:** Make `OVLSTUB_22_3744` / `OVLSTUB_22_36CA` (two of the analyzer's ~3
  known un-thunked jump-table stubs) decompile as their targets.
- **Friction:** No tool can convert a plain function into a thunk of another
  (legacy playbook used `fm.createThunkFunction` from a script; there is no
  script-execution tool by design).
- **Expected:** e.g. `create kind=thunk` with `address` + `target`.
- **Workaround:** Renamed the stubs `jmp_Dialog_RunByKey` / `jmp_Dialog_RunFromText`
  with plate comments carrying the original stub identity.

## 2026-07-08 — gap — no struct-field rename
- **Task:** `colony_t.unkd` turned out to be the per-nation seen-pop/seen-fort
  arrays; wanted to rename the fields so every colony decompile improves.
- **Friction:** `manage_types` only renames/deletes whole types; redefining the
  struct via `define_types`/`set_data_type kind=struct` risks clobbering the
  carefully built `colony_t`.
- **Expected:** `manage_types op=rename_field` (name + field offset/old name).
- **Workaround:** Left field names alone; documented meaning in plate comments.

## 2026-07-08 — inspect — namespaced symbol paths don't resolve
- **Task:** Find the address of the switch-case label the trampoline `281f:0c4a`
  jumps to.
- **Friction:** `inspect location="switchD_1000:2c03::caseD_6"` (the exact name
  `decompile` printed) → `No symbol or address`. Related nit: `disassemble`
  `address="find_adjacent_water_tile"` errors — per the operand convention
  `address` is strictly an address, but muscle memory says otherwise after
  `location`/`function` accept names.
- **Expected:** namespace-qualified lookup for `location` operands, or the
  decompiler emitting resolvable names.
- **Workaround:** `xrefs direction=from` on the trampoline's JMPF instruction
  address gave the target (`15eb:096e`).

## 2026-07-08 — RESOLVED (plugin) — batch save, thunk, field rename, namespaces, RETF hint (commit `af2e3a5`)
- **batch "error yet applied":** the edits commit, but they fire `FUNCTION_CHANGED`
  events → `AutoAnalysisManager` schedules background analysis holding its own
  transaction, and the follow-up save then failed the lock. Save now settles first
  (`ProjectContext.saveSettled`: flush events → `waitForAnalysis` → flush → save, bounded
  retry; the single-edit save path shares it). Verified live: a rename batch returns
  "2 ok, 0 failed" with no lock error.
- **inspect namespaced symbols:** `location`/`function` operands now resolve
  `namespace::symbol` paths (e.g. `switchD_1000:2aa7::caseD_6`) via `NamespaceUtils`.
  Verified live → `1000:0000`. (The `disassemble address=<name>` nit is left as-is: `address`
  is the strict-address operand by design; use `location`/`function` for name lookups.)
- **manage_types op=rename_field:** rename a struct/union field by current name or byte
  offset (`0x1a`/decimal). Verified (by name and by offset).
- **set_function_signature RETF hint:** applying a near calling convention to a function
  whose body ends in `RETF` (far) now appends a ⚠ warning that stack params may be
  misplaced (`Stack[0x2]` vs `Stack[0x4]`); pass `calling_convention=__cdecl16far`.
- **create kind=thunk** (`address` + `target`): sets the thunk relationship so the call
  graph resolves stub → target (verified: `calls` on `281f:03fe` now resolves
  `Dialog_RunByKey`). **Caveat:** for RTLink dispatch stubs whose body is un-decodable "bad
  instruction data", the decompiler still renders that body rather than the target — the same
  Ghidra limitation that leaves the analyzer's own such stubs un-followable. So the thunk is
  wired, but "decompile as the target" is not achieved for those specific stubs.
