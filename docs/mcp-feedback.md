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
- **Task:** colony_create annotation pass — two `batch` calls (49 and 13 edits) of
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
- **Task:** Give the 281f far trampolines real prototypes so colony_create's call
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
- **Workaround:** Renamed the stubs `jmp_dialog_run_by_key` / `jmp_dialog_run_from_text`
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
- **create kind=thunk** — shipped, then **removed** (commit `9602186`). The RTLink analyzer
  was fixed to auto-thunk every statically-resolvable stub + resident trampoline (fork
  `ad67f1fc7d`/`c5f4b407c7`), so wiring stub → target is no longer the plugin's job. And the
  real goal — making the overlay-dispatch stubs *decompile as their targets* — is impossible:
  their `JMPF` targets unmapped `0000:xxxx` in the resident space while the target lives in a
  separate overlay space, so the decompiler renders the stub's bad body regardless of the
  thunk record. Confirmed against a fresh analyzer run: `OVLSTUB_22_3744` is a proper
  analyzer-created thunk yet still decompiles as `FUN_210d_0dab(0x281f); halt_baddata()`. A
  manual thunk tool only wired the call graph (which the analyzer now does) and never
  delivered decompile-as-target, so it was retired. Use the RTLink One-Shot analyzer for stub
  thunking.

## 2026-07-08 — gap — no way to delete a symbol/label
- **Task:** Naming-convention sweep: `g_players` existed at both 2b5a:540e (real
  array base, verified via `savegame_read_file` fread dest) and 2b5a:540f (stale
  off-by-one label). Wanted to delete the stray.
- **Friction:** No delete op anywhere: `rename` has no "remove" semantics
  (`new_name: ""` did not delete — the call timed out and left the label), `clear`
  only does code-units/local-variables, `create` only creates.
- **Expected:** `clear kind=label` (or `symbol`) with `address`, symmetric with
  `create kind=label`.
- **Workaround:** Renamed the strays `g_players_stale_dup` /
  `g_indian_relations_stale_dup` with EOL comments saying to delete them.

## 2026-07-08 — batch — 264-edit rename batch: response timed out, edits applied; write lock stuck ~5 min
- **Task:** Convention sweep applying 264 renames in two `batch` calls (132 + 132).
- **Friction:** First 132-edit batch returned fine (~all renames echoed). Second
  batch call **timed out client-side but fully applied** (verified via `inspect` on
  first and last targets). Afterwards every write tool (`rename`, `batch`) timed out
  for ~5 minutes while `read_log` showed an exponential-backoff "Invoking analysis
  worker (Wait for Analysis)" loop; reads (`inspect`, `search_memory`) kept working.
  One retry ~4 min later also died ("Unable to connect", session reset); the next
  retry succeeded cleanly.
- **Expected:** batch to bound its post-edit save/analysis wait (or return
  "applied, save pending") instead of holding the write lock past the MCP client
  timeout; a way to query "is the program busy/locked".
- **Workaround:** Verified effects with `inspect` before retrying (rename-by-address
  retries are idempotent), polled `read_log`, waited out the lock.

## 2026-07-08 — xrefs/inspect — data-label xref counts are 0 for DS globals
- **Task:** Disambiguate duplicate data labels (`g_savegame_head` 5370 vs 5380) by
  finding which one code references.
- **Friction:** `inspect` reported "Xrefs: 0 to" for heavily-used globals
  (`g_players`, `g_savegameHead`, …) — 16-bit DS-relative operands evidently carry
  no xrefs, so neither `inspect` nor `xrefs` can answer "who uses this global".
- **Expected:** Some path from a DS global to its readers/writers.
- **Workaround:** `search_memory` for the address-immediate byte pattern
  (`68 0e 54` = PUSH 0x540e) — worked, and the hit list's "in <function>+0x…"
  tagging made it painless. Decompile of the reader confirmed.

## 2026-07-08 — application-level / decompile — no "save program" tool; thunk body reads as un-thunked
- **Task:** Iterate on the RTLink analyzer: edit → restart Ghidra (no hot-swap) →
  One Shot on VICEROY.EXE → verify thunk/convention state.
- **Friction:** (1) There is no "save program" tool. Restarting Ghidra to load an
  analyzer rebuild silently drops any unsaved DB state, and I couldn't force a save
  or query "are there unsaved changes"; combined with a second agent on the same
  shared instance, DB state (names) appeared to flip across restarts. (2)
  `ghidra-program decompile` on an in-place thunk (made via `setThunkedFunction` on a
  function that keeps its `CALLF+JMPF` body) renders the thunk's *own* body with a
  "WARNING: Bad instruction" line — it reads as "not a thunk", causing a wrong
  conclusion; only a direct `isThunk` check (via a temporary analyzer log) disproved
  it. `inspect` also doesn't surface thunk-ness / thunked-target.
- **Expected:** a `save`/`is_dirty` capability (or a documented auto-save contract),
  and for `inspect` to report `isThunk` + thunked-function so thunk status doesn't
  have to be inferred from decompiler output.
- **Workaround:** imported a fresh private copy (`/rtlink-session-test/VICEROY.EXE`)
  to test in isolation; added temporary `MessageLog` tracing in the analyzer to read
  `isThunk()` straight from the FunctionDB.

## 2026-07-08 — clear/create — no delete-function, no body override, save blocked by other txn
- **Task:** Reconcile main `/VICEROY.EXE` to a clean fresh-import baseline: turn one
  old-style `uint` (`112b:0790`) back into its function and merge it with a spurious
  user function `draw_indian_village_marker` mis-anchored mid-instruction at `112b:0a04`
  (clean has one 1234-byte function there; main had data + a mid-body function).
- **Friction:** Three gaps, all around function-body editing:
  1. **No delete-function op.** To merge, the spurious `0a04` function must be removed
     (keep its code). `clear kind=code` over the range does NOT remove the function —
     it persists / is auto-restored (the entry is a live call target), so the split
     never goes away. Nothing exposes Ghidra's "Delete Function". I had to ask the
     human to delete it in the GUI.
  2. **No way to force a function-body recompute or set an explicit body range.** After
     the split boundary was gone, `FUN_112b_0790`'s body stayed stale at 642 bytes and
     would not absorb the freed middle block: `create kind=function` on an existing
     function is a no-op for the body, `clear` won't drop it (call-ref auto-restores at
     642 B), and neither `analyze "Decompiler Switch Analysis"` nor re-analysis
     recomputes an existing body. Ghidra's GUI "Create Function" over a *selection*
     forces a body; `create kind=function` takes only an `address` (no `end`/body-range,
     no `recompute`/`reflow` flag), so there is no MCP equivalent.
  3. **Save silently blocked by a concurrent transaction.** A `create` returned
     `Edit applied but saving '/VICEROY.EXE' failed: Unable to lock due to active
     transaction` — the edit applied in memory but did not persist (a second agent /
     background analysis held the write lock). No way to detect/wait for the lock; a
     bare `create` doesn't retry.
- **Expected:** (a) a delete-function op (e.g. `clear kind=function`, or a `delete`
  tool) that removes the function but keeps code/label; (b) either a body override on
  `create kind=function` (`end_address`/`body` range) or a `reanalyze_function` /
  `recreate` that forces a fresh body computation like GUI Create-Function-over-selection;
  (c) save-lock handling — auto-retry, or a "program busy/locked" signal so the caller
  knows the edit did not persist. `batch` (which saves once and continued past the lock)
  was the only way to get the change to stick.
- **Workaround:** human deleted the `0a04` function in the GUI; when the merge still
  wouldn't take (body wouldn't recompute — main's flow genuinely splits where the clean
  import over-merged), re-created `draw_indian_village_marker` to avoid leaving orphan
  code, and persisted via a one-op `batch` to dodge the save-lock. Net: the essential
  fix (data → function, trampoline thunks) landed; the exact 1234-byte merge did not.

## 2026-07-08 — RESOLVED (plugin) — deletion ops, thunk-status, body range, bounded save (commit `79552ff`)
Addresses the deletion / body-edit / save-lock cluster (the "no delete symbol/label",
"264-edit batch lock stuck ~5 min", "no save-program tool / thunk-status", and
"no delete-function, no body override, save blocked by other txn" entries).
- **`clear kind=label`** — deletes a user label at `address` (pass `name` to pick one when
  several share it); refuses a function symbol (that would delete the whole function). Verified
  live: created + deleted a scratch label.
- **`clear kind=function`** — deletes the function (Ghidra Delete Function) but **keeps its code
  and labels**. Verified live: `strcpy` became a plain label with its instructions intact, then
  re-created cleanly. Recompute-from-flow = `clear kind=function` then `create kind=function`.
- **`create kind=function end_address`** — forces the body to an explicit inclusive range (works
  on an existing function). Verified live restoring `strcpy`'s 50-byte body.
- **Bounded, deferring save** — `saveSettled` no longer waits on all analysis; it polls the
  non-throwing `canLock()` with a short backoff and, if the program stays busy, returns
  *deferred* rather than holding the write lock for minutes. Edits that can't save immediately
  come back with "(save deferred — program busy; run save when idle)" instead of an error; the
  264-edit lock-stuck case is gone. New **`save`** tool flushes deferred edits (longer bound);
  **`get_program_info`** now shows `Unsaved changes: yes|no` (and already flagged analysis in
  progress). Verified live: edits save cleanly with no deferral note; dirty flag shows.
- **`inspect` thunk-status** — a function that is a thunk now prints `thunk → <target>`, so it
  isn't misread from a decompile of its own body. Verified live on `281f:0056` → `flashmsg_erase`.
- **Not fixed (fundamental):** a bad-body overlay-dispatch stub still *decompiles* as its stub
  body even when thunked (see the create-kind=thunk removal note) — `inspect` thunk-status is the
  reliable signal instead. **DS-relative data-label xrefs** (the "xref counts are 0" entry) remain
  a 16-bit limitation; `search_memory` for the address-immediate byte pattern is the path.
