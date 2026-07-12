# ebbex-ghidra-mcp — Dogfooding Feedback (Archive)

Resolved friction moved out of [mcp-feedback.md](mcp-feedback.md) to keep the active log
focused on open items. Each entry below was reproduced, fixed, and verified live; the
resolution notes cite the commits. Newest last.

---

## 2026-07-07 — decompile silently truncates on corrupted overlay bytes — dropdown-menu RE
- **Task:** Reverse-engineer `Menu_BuildMenuBar` (OVERLAY_24::010000) to find the
  separator/visibility/color logic for the top menu-bar dropdowns.
- **Friction:** `decompile` on this function returned a plausible-looking ~6-line C
  function (one `menubar_create` call, one `read_text_section` call, an early bail,
  a `text_close_file` call) with no error/warning surfaced to the caller. The real
  function is ~2800 bytes and calls `menubar_add_menu`/`menu_add_item` roughly 100
  times. Nothing in the tool's response indicated the decompile was wrong — I only
  found out because a prior session had already left a plate comment on this exact
  function warning that "this page's DB bytes are corrupted at relocation fixup
  sites... disassembly verified against the raw EXE," which I could have easily
  missed (blind-analysis agents are explicitly told not to read that doc). Ended up
  re-deriving the entire ~700-instruction control flow from `disassemble` by hand
  (had to call it with `count: 400` to get the whole function in one shot, then
  manually pair up `PUSH`/`CALLF` sequences into logical calls since the far-call
  ABI here splits each argument across several push sites around nested calls).
- **Expected:** Ideally the decompiler (or the MCP wrapper) would flag when its
  output covers dramatically less code than the function's actual byte range /
  instruction count — e.g. a "decompile confidence: low, N instructions not
  represented" note — so a caller doesn't trust a short, clean-looking decompile
  that's actually wrong. Barring that, it would help if `inspect` or `decompile`
  surfaced "body N bytes" alongside the C output so a suspiciously short decompile
  of a suspiciously long function is easy to notice without cross-referencing
  `disassemble`.
- **Workaround:** Used `disassemble` with a large explicit `count` and manually
  traced the calling convention (far-pointer args split as separate word pushes,
  several pushed *before* a nested `CALLF` whose return value becomes another
  argument) by hand against known-good decompiles of the callees
  (`menu_add_item`, `menubar_add_menu`) to recover argument order.

## 2026-07-07 — xrefs/calls both miss indexed/pointer-relative data & jump-table references
- **Task:** Find callers of `menu_item_set_hidden`/`menu_item_set_disabled` (per-item
  show/hide setters in OVERLAY_08) to see what drives dynamic menu-item visibility,
  and find code that reads the believed menu-color bytes at DS:0x830/0x831.
- **Friction:** `calls kind=callers` on the functions themselves, on their
  jump-table stubs (`OVLSTUB_09_05C6`/`OVLSTUB_09_0552`), and `xrefs
  direction=to` on both the stub and the real target all returned **0 results**
  for all four. Likewise `xrefs` on `2b5a:0830`/`2b5a:0831` returned "No to
  references" even though a direct byte read confirms the exact expected values
  (0x44/0x95) sit there. This is consistent with the project's documented gap
  ("some far-call sites into the jump table may still lack xrefs") but I had no
  way to positively distinguish "genuinely zero callers" from "xref resolution
  gap" other than the raw-CALLF-byte-search fallback in `docs/ghidra-workflow.md`
  — and that fallback itself came up empty here (searched `9a <off> <seg>` for
  both stub addresses across the whole image), which is itself informative but
  took several extra round-trips to confirm.
- **Expected:** No specific missing tool — `search_memory kind=bytes` covered the
  raw-CALLF fallback fine — but it would save round-trips if `xrefs`/`calls`
  optionally reported "0 direct refs, but N indexed/computed accesses reference
  this region" when it can detect register-relative or table-computed accesses
  near a given address, since that's the exact ambiguity that cost the most time
  here (is this dead code, or just an xref gap?).
- **Workaround:** Cross-checked with `search_memory kind=bytes` for the literal
  `9a <offset-LE> <segment-LE>` CALLF encoding of each stub's address across the
  whole image; got zero matches too, which (combined with the same result for two
  independent functions) was treated as reasonably strong evidence the functions
  are genuinely uncalled in this build, rather than just an xref gap.

## 2026-07-07 — RESOLVED (plugin) — both entries above addressed in ebbex-ghidra-mcp
- **decompile silent truncation:** `decompile` now leads every function with a coverage
  header — `// <name>  body <N> bytes, <M> instrs, decompiler represented <K> (<pct>%)` —
  and appends `⚠ LOW COVERAGE` when the decompiler reached < 50% of the function's
  instructions (measured against its basic-block ranges, so optimization doesn't cause
  false alarms) or didn't complete. Verified live: `Menu_BuildMenuBar` now reports
  `body 2826 bytes, 945 instrs, decompiler represented 29 (3%) ⚠ LOW COVERAGE`; healthy
  functions (`menu_add_item` 96%, `strcpy`/`strcat`/`rand_range` 100%) show no warning.
- **xrefs/calls bare zero:** a zero-result `xrefs direction=to` / `calls kind=callers`
  now prints an explicit caveat that Ghidra doesn't track unresolved computed/indirect
  refs (jump tables, far calls, register-relative data) and to confirm with
  `search_memory kind=bytes`, instead of a bare "No references". Existing refs are tagged
  `computed`/`indirect`. Verified live on `2b5a:0830` (the DS:0x830 menu-color bytes) and
  a zero-caller overlay function; `direction=from`/`callees` are unchanged.
- **Root cause of the OVERLAY_24 corruption is NOT the plugin** — it's the RTLink overlay
  analyzer applying relocation fixups to non-segment words (the plate comment on
  `Menu_BuildMenuBar` confirms: "importer added 0x1000 to non-segment words … verified
  against the raw EXE, page 24 @ file 0x72090"). A separate fix is planned in the Ghidra
  fork (`ghidra/rtlink/docs/analyzer-fixup-fix-plan.md`); the plugin change above is the
  detection tripwire, not the cure. The missing-xref cases (jump-table dispatch,
  register-relative `DS:0x830`) are a fundamental 16-bit static-analysis limit, hence the
  honest caveat rather than a claimed fix.

## 2026-07-07 — RESOLVED (Ghidra analyzer) — OVERLAY_24 truncated decompile root-caused; corruption claim was wrong
- **The relocation-corruption theory is disproven.** All 757 relocation fixup sites of
  page 24 (block OVERLAY_24, code @ file 0x72090) were checked against the raw EXE:
  every site lands exactly on a CALLF/JMPF segment operand word, every loaded word is
  raw_word+0x1000, and the raw words take only five values (0x181f/0x191f/0x1a1f/
  0x0d1d/0x1b22 → the resident stub segments 281f/291f/2a1f/1d1d/2b22). The earlier
  plate comment on `Menu_BuildMenuBar` ("importer added 0x1000 to non-segment words")
  and the root-cause note in the entry above were wrong; the plate comment has been
  corrected in the project.
- **Actual cause:** stale no-return flags on three overlay functions (`text_read_line`,
  `menu_add_item`, `building_def_set`), left behind by an earlier analyzer iteration.
  Ghidra's no-return discovery mis-fires on RTLink dispatch stubs while overlay flow is
  unresolved (the stub's `JMPF 0000:offset` decodes as a jump into unmapped memory), and
  `setNoReturn(true)` on a stub thunk delegates to its overlay target. The decompiler
  then treated every call through any stub forwarding to those targets as non-returning
  and silently dropped the rest of the calling function — hence the clean-looking 6-line
  decompile of a 2826-byte function.
- **Fix (ghidra fork, `rtlink` branch, commit e51df8c398):** `createThunkAtStub()` now
  clears a no-return flag on the overlay target when its disassembled body provably
  returns, and clears discovery flags on plain-function stubs before thunk conversion;
  a new `repairStubThunks()` retrofit re-runs stub wiring idempotently on already-
  analyzed programs via Analysis → One Shot → "RTLink/Plus Overlay", so annotated
  projects are repaired in place without re-importing.
- **Verified live on VICEROY.EXE:** `Menu_BuildMenuBar` 3% → 99% decompiler coverage
  (full ~100-call menu-building body, matches the disassembly), `Europe_ShipOrdersMenu`
  46% → 97%, `building_def_set`/`tileset_load_ss` 100%, `text_read_line` 94%; no
  regressions in spot checks across OVERLAY_02/22/24. The plugin's coverage header
  (entry above) remains the tripwire that would catch any recurrence.

## 2026-07-07 — missing capability (now added) — no way to read this instance's application.log over MCP
- **Task:** Chase analyzer behaviour (e.g. "could not create stub thunk" / auto-analysis
  "Analysis Log Messages") that surfaces only in `application.log` — those messages never
  appear in tool results, so the log is the sole post-hoc window into analysis.
- **Friction:** Finding the *right* log cost several round-trips. The obvious
  `~/.config/ghidra/.../application.log` belongs to a different Ghidra instance (the
  installed distribution with the `rtlink-dsfix.jar` patch); the Eclipse-launched dev
  Ghidra actually logs under the flatpak sandbox at
  `~/.var/app/org.eclipse.Java/config/ghidra/ghidra_12.1.2_DEV_location_rtlink/application.log`.
  Grepping the wrong file silently gives misleading answers (reading July-5 headless
  entries as today's fresh-import run). No tool exposed the log or even its path.
- **Expected:** A tool that reads the running instance's log — the server lives inside the
  Ghidra process, so it can resolve the path unambiguously rather than guessing.
- **RESOLVED (plugin):** new application-level `read_log` tool (commit `2cfce90`). It
  resolves the path in-process via `LoggingInitialization.getApplicationLogFile()` (the
  same call the Front End "Show Log" uses), so there's zero ambiguity about which
  instance's log you get; the resolved `Log:` path leads every response. Tails the last N
  matching entries (newest last) with an optional case-insensitive substring or `regex`
  `filter` and a lexical `since` timestamp cutoff, keeping multi-line stack traces whole;
  streaming keeps memory O(tail). It runs even with no project open (import/startup
  failures), and `get_application_info` now breadcrumbs the log path. Verified live: the
  path resolves to the flatpak dev instance (not the installed dist), and
  `filter="2026-07-07.*RTLink" regex=true` reproduces the exact grep that prompted this.

## 2026-07-07 — decompile's synthetic `xRamNNNNNNNN` globals aren't valid `inspect`/`rename` addresses
- **Task:** Identify VICEROY's live map-tile renderer (OVERLAY_19) globals — e.g. the
  per-tile working-class byte and the current-nation fog mask — while tracing the
  ocean/sea-lane water-water blend condition in `draw_coast_edges`.
- **Friction:** `decompile` on `draw_map_tile`/`build_coast_neighbor_mask_edge_probe`
  named unresolved globals `bRam00035e3e`, `bRam00035e42`, etc. (an 8-hex-digit tag after
  the type-prefix letter). These look like addresses but aren't real Ghidra addresses —
  `inspect location=bRam00035e3e` fails with `IllegalArgumentException: No symbol or
  address 'bRam00035e3e'`. The tag turned out to encode a **linear address**
  (`segment*16+offset`, e.g. `0x35e3e = 0x2b5a*16 + 0xa89e`), which isn't documented
  anywhere in the tool descriptions and isn't a form `inspect`/`rename`/`read_bytes`
  accept directly (they want `seg:off`). Had to re-derive the real `seg:off` by
  `disassemble`-ing the same function and reading the concrete `[0xNNNN]` operands next
  to the matching instructions, then manual hex subtraction to confirm the mapping.
- **Expected:** Either have `decompile` name these globals in `seg:off` form to begin
  with (matching what `inspect`/`rename`/`disassemble` all accept), or have
  `inspect`/`rename` accept the same `xRamNNNNNNNN` linear-address form the decompiler
  already emits, so a variable name copy-pasted straight out of a decompile is usable
  without a manual base-address conversion.
- **Workaround:** `disassemble` the same function and read the raw `[0xNNNN]` operand
  next to the corresponding `MOV`/`CMP`/`TEST`, then treat that hex literal as the
  `seg:off` offset (segment = the function's own DS, 0x2b5a here) for `inspect`/`rename`.

## 2026-07-07 — `rename kind=label` requires a pre-existing symbol; `create kind=label` is the one that works on bare addresses
- **Task:** Label `2b5a:a89e` (the per-nation fog-of-war visibility mask consulted by
  both `draw_map_tile` and `draw_coast_edges`) so the finding is discoverable by name.
- **Friction:** `rename kind=label address=2b5a:a89e new_name=g_currentVisibilityMask`
  returned `No symbol at 2b5a:a89e` — the address is a plain byte inside the `DATA`
  block with no auto-generated symbol (unlike the `SUB_OVERLAY_19__0111d4` case earlier
  in the same session, which *did* have an auto label and renamed fine). Had to fall
  back to `create kind=label` at the same address with the same name, which succeeded.
  Both tools are documented and this isn't really a bug, but the failure mode ("No
  symbol at X") doesn't hint that `create` is the fix — worth remembering that
  `rename kind=label|data` only works on addresses Ghidra already auto-labeled
  (BSS/data with no symbol yet needs `create kind=label` first).
- **Expected:** No change requested — noting it here mainly so the next agent doesn't
  waste a round-trip guessing between the two tools for a bare, never-before-labeled
  data address.

## 2026-07-07 — RESOLVED (plugin) — `xRamNNNNNNNN` globals resolve; clearer bare-address rename error
- **Decompiler `Ram` globals now resolve (commit `b3a774d`):** `Locations` accepts the
  decompiler's synthetic `<prefix>Ram<flat-hex>` names (e.g. `bRam00035e3e`,
  `uRam00001234`) copied straight out of a decompile. The 8-hex tail is the flat/linear
  address (`segment*16+offset`), which the address factory maps to the right byte; the
  resolved address is then re-expressed using the containing block's base segment
  (DGROUP/DS `2b5a`), so it echoes as the `seg:off` you see in disassembly. A small
  fallback in the shared `toAddress()` gives it to every Locations-based tool at once.
  Verified live: `inspect location=bRam00035e3e` → `2b5a:a89e g_currentVisibilityMask`,
  `bRam00035e42` → `2b5a:a8a2 g_curTileClass`; `read_bytes` resolves the same (a
  `MemoryAccessException` there just means the DATA block is uninitialized). Normal
  symbol/`seg:off`/bare-hex resolution is unchanged.
- **Bare-address rename error (commit `b3a774d`):** `rename kind=label|data` on an address
  with no symbol now says to use `create kind=label` to make a new label, instead of a bare
  "No symbol at X".

## 2026-07-07 — no way to inspect a function's local-variable records — DB-vs-decompiler divergence invisible
- **Task:** Debugging why a decompiler local rename silently reverts
  (`decompiler_quirk.md`): needed to see what `rename kind=local_variable` actually
  wrote to the program DB for `Colony_Create` — the variable's storage (register /
  stack / HASH), first-use offset, and source type.
- **Friction:** `rename` reported success and `decompile` showed the name reverted,
  but nothing could show the persisted `Function.getLocalVariables()` records.
  `inspect location=Colony_Create` shows signature/comments only; `list
  kind=symbols filter=col` returns no function-local symbols at all (labels and
  functions only), so a successful-looking rename and a failed one are
  indistinguishable.
- **Expected:** either `inspect` on a function listing its DB variables (name,
  storage, first-use address, source), or a `list kind=locals
  function=<f>` variant.
- **Workaround:** rebuilt the whole commit/restore pipeline outside the plugin
  (C++ `decomp_dbg` console + reading `HighFunctionDBUtil`/`LocalSymbolMap`
  sources) to infer what the DB must contain.

## 2026-07-07 — decompiler-internals introspection gap — no equivalent of DecompInterface debug dump
- **Task:** Same bug: needed to see what the Java side *sends* the decompiler
  process on a decompile request (the `<mapsym>`/`<hash>` symbol encodings) to
  compare against what the C++ side computes.
- **Friction:** No tool exposes the decompiler XML exchange or per-variable
  `HighSymbol`/`DynamicEntry` info (hash value, pc address, storage) for a
  decompiled function.
- **Expected:** a debug flag on `decompile` (dump symbol mappings, or the
  DecompInterface debug XML) — even truncated — would have located the
  Java/C++ hash mismatch in one call.
- **Workaround:** hand-built a synthetic ELF, imported it, and A/B-tested rename
  persistence on x86-64 vs x86-16 to triangulate; root-caused by reading both
  hash implementations side by side.

## 2026-07-07 — RESOLVED (plugin) — function variables now visible: inspect DB records + decompile HighSymbol dump (commit `82c81be`)
- **DB variable records (entry 1):** `inspect` on a function entry now appends a
  `Variables:` section listing the persisted parameters and locals — name, data type,
  storage (`Stack[..]`/register/`HASH:<hash>`), first-use offset (`fu=`), and source type.
  A `kind=local_variable` rename writes exactly these, so a successful rename is now
  distinguishable from one the decompiler silently reverted. Verified live:
  `inspect location=Colony_Create` lists the four stack params, `AX`/`AL` register locals,
  and two `HASH:..` dynamic locals with their offsets.
- **Decompiler-internals dump (entry 2):** `decompile` gained an opt-in `dump_symbols=true`
  flag that appends the decompiler's HighSymbol table — each local/param's name, storage,
  and data type, plus **hash + pc address for dynamic (hashed) locals** — enough to spot a
  Java/C++ hash mismatch in one call. Off by default. Verified via the headless smoke run.

## 2026-07-08 — no way to delete a function local variable — stale HASH locals are permanent
- **Task:** Cleaning up after the rename-persistence bug fix (`decompiler_quirk.md`):
  the pre-fix failed renames left dead dynamic locals in the DB whose stored hashes
  (computed with the old broken Java convention) can never re-attach — `col_stale` +
  `puVar2` in `Colony_Create`, `col_stale` in `Colony_ProcessTurn`. They occupy their
  names in the function namespace (a fresh `rename ... new_name=col` fails with
  "A Local Var symbol with name col already exists") but never appear in decompiled
  output, so they can't be targeted for anything except another rename.
- **Friction:** No tool deletes a local variable. `rename kind=local_variable` was the
  only mutation available, so the best I could do was rename the corpses aside
  (`col` → `col_stale`).
- **Expected:** a delete op for function variables, e.g. `clear` gaining
  `kind=local_variable` (function + variable_name) or a `manage_variables` tool —
  equivalent to Ghidra's "Delete Variable" action / `Function.removeVariable()`.
- **Workaround:** renamed stale variables to `*_stale` and left them in the DB.
- **RESOLVED (plugin, commit `0d52d91`):** `clear` gained a `kind` discriminator —
  `kind=code` (default) is the existing address-range clear; `kind=local_variable`
  (`function` + `variable_name`) deletes the local via `Function.removeVariable` (Ghidra's
  Delete Variable). Mirrors the `kind=local_variable` that `rename`/`set_data_type` already
  carry. A name that resolves to a parameter is rejected with a pointer to
  `set_function_signature`. Verified live: deleting `puVar2` from `Colony_Create` removes it
  from the `inspect` Variables list. (The remaining named corpses — `col_stale` in
  `Colony_Create` and `Colony_ProcessTurn` — can now be cleared the same way.)

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

### 2026-07-08 — closed the `112b:0790` merge with these ops (no GUI, no human step)
The exact 1234-byte merge that the earlier entry left unfinished is now done end-to-end over MCP:
1. `clear kind=function draw_indian_village_marker` — dropped the spurious `0a04` function
   (mis-anchored mid-instruction, in the middle of the `(BX*9 + SI)*2` index calc into `0x54f6`),
   keeping its code.
2. `create kind=function address=112b:0790 end_address=112b:0c61` — forced `FUN_112b_0790`'s body
   from the stale 642 bytes to the full 1234 (the recompute that previously wouldn't take).
3. `clear kind=label 112b:0a04 name=draw_indian_village_marker` — removed the misleading leftover
   label so `0a04` is plain interior code, matching the clean baseline.
`save` reported "No unsaved changes" (auto-saved). Trampoline `2000:84a2 → thunk_FUN_112b_0790 →
FUN_112b_0790` stayed intact. This was the last unreconciled address vs the clean end-product; the
"main's flow genuinely splits" caveat in the prior entry was wrong — the split was a spurious
mid-computation boundary, confirmed by disassembly at the join. No `batch` save-lock dodge or human
GUI action needed.


## 2026-07-08 — gap — no custom (register) parameter storage; register-passed params un-nameable
- **Task:** pretty up `surface_fill_rect` (`1b9e:000a`), a 16-bit graphics primitive with a
  **mixed convention** — x in AX, y in DX, width in BX (registers), color/height/descriptor on
  the stack. Wanted to name all inputs, including the register-passed x/y/width.
- **Friction:** only the stack params surfaced as named variables. `width` (BX) and the segment
  (DX) could be reached via `rename kind=local_variable` on the decompiler's `in_BX`/`in_DX`
  aliases, but the **x coordinate (AX) never appears as a variable at all** — it is stored to a
  stack slot and consumed by-address into `surface_clip_rect`, so there is nothing to rename.
  `set_function_signature` couldn't help: a plain C prototype forces all params to stack storage.
  There was no way to declare custom storage (`x @ AX, y @ DX, width @ BX`) over MCP. Related:
  `surface_pixel_addr` (`1a4e:0008`) returns a **far pointer in DX:AX** (segment in DX = `desc[+6]`),
  but its recovered return type was plain `int`, so DX was invisible in C and the caller read a
  phantom `in_DX`.
- **Resolution:** `set_function_signature` now takes a `parameters` array with per-param `storage`
  — a register (`AX`), a register pair (`DX:AX`), or a stack slot (`Stack[0x4]`) — plus an optional
  `return` `{type, storage}`. Verified live:
  - `surface_pixel_addr` pinned to `(x@AX, y@DX, desc@BX) -> ulong @ DX:AX`; it now decompiles as
    the one-liner `return CONCAT22(desc->base_seg, desc->pitch*y + desc->base_off + x);` — the DX
    segment half is fully modeled. Added a `surface_desc` struct (`define_types`) for the `desc`
    param and applied it to `g_screenBufDesc1`.
  - `surface_fill_rect` pinned to `(x@AX, y@DX, width@BX)` + the six stack params. The phantom
    `dst_seg`/`in_DX` disappeared, and the decompiler now recognizes the four stack words as the
    descriptor: `surface_pixel_addr(x, y, (surface_desc *)&dst_height)`.
  - Gotcha: a pre-existing local named `width` (an earlier `in_BX` rename) blocked the param name;
    `clear kind=local_variable` on it, then the signature set, resolved it.

## 2026-07-09 — create kind=label could not target a namespace — jump-table override
- **Wanted:** write a decompiler jump-table override, which Ghidra encodes purely as symbols:
  a namespace `<func>::override::jmp_<branchaddr>` holding a `switch` label at the branch and
  `case_N` labels at each destination (see `JumpTable.writeOverride`).
- **Friction:** `create kind=label` called `symbolTable.createLabel(addr, name, source)`, which
  always lands in the global namespace. No way to build the hierarchy. And once a `namespace`
  argument existed, there was still no way to *inspect* whether the decompiler consumed the
  override — `getJumpTables()` is Java-side only and the C++ result gives no signal, so debugging
  it took several full re-decompiles with no feedback.
- **Resolution** (ebbex-ghidra-mcp `5edf42d`, then `b221d70`):
  - `create kind=label` takes an optional `namespace`, a `::`-separated path walked (and created)
    from the global namespace.
  - **The first cut was broken and the verification was too weak to catch it.** `5edf42d` resolved
    each path segment with `SymbolTable.getNamespace(name, parent)`, which deliberately does *not*
    resolve functions (its javadoc: "namespace…, class…, or library…, but not a function", because
    function names may be duplicated within a parent). So `FUN_x::override::jmp_y` silently created
    a *plain namespace* named `FUN_x` beside the function and put the labels under it, where
    `HighFunction.grabOverrides` — which looks under the Function — never sees them. The original
    "Verified: `list kind=symbols` shows the labels fully qualified" was exactly the evidence that
    could not distinguish the two: both print the same `FUN_x::override::jmp_y::switch` path.
    `b221d70` switches to `NamespaceUtils.getNamespacesByName`, which matches on
    `SymbolType.isNamespace()` — a predicate functions satisfy.
  - `decompile` gained `dump_jumptables`: it prints the `<jumptablelist>` XML the Java side
    transmits (reconstructed with `HighFunction.grabFromFunction`, the same call
    `DecompileCallback.encodeFunction` makes) and a per-switch verdict — `CONSUMED (n cases -> m
    distinct targets)` / `NOT CONSUMED` / `decompiler-discovered`. Recovered tables are summarised
    rather than dumped, since they repeat one `<dest>` per case value. It is emitted after a *failed*
    decompile too, because a bad override is a common reason the decompiler bails.
- **Verified** end-to-end on `/bin/ls`'s `get_funky_string` (a real 73-case switch at `00103b65`):
  before any override → `decompiler-discovered (73 cases -> 13 distinct targets)`; after writing
  `switch` + `case_0..2` through `create kind=label namespace=…` → `<basicoverride>` with the three
  destinations in the sent XML and `CONSUMED (16 cases -> 3 distinct targets)`; with the `switch`
  label moved off the branch → `NOT CONSUMED`. The smoke script now asserts
  `HighFunction.findOverrideSpace(func) != null` after a namespaced `create`, which fails against
  the `5edf42d` behaviour.

## 2026-07-09 — manage_files cannot delete a folder — analyzer-testing cleanup
- **Wanted:** clean up after analyzer testing — several `/scratch-*` folders, each holding one
  re-imported `VICEROY.EXE`.
- **Friction:** `manage_files(op=delete)` removed the programs fine, but the now-empty folders
  stayed. `op=delete` on a folder path returned `No project file: /scratch-final`; the op only
  resolved files. The project went from 2 folders to 6 with no MCP way back — it needed a
  right-click → Delete in the GUI project tree. Cleanup is the natural bookend to
  `import(folder=…)`, which happily *creates* folders.
- **Resolution** (ebbex-ghidra-mcp `b221d70`): all three ops resolve a folder as well as a file.
  Folder delete is empty-only unless `recursive=true`, which walks depth-first like Ghidra's own
  `DeleteProjectFilesTask` and — having no way to prompt as the GUI does — refuses on open,
  versioned, or read-only files, naming them. Cached program handles under the folder are released
  first, since `ProjectContext` keys its cache by exact path. `op=move` refuses a destination
  inside the folder being moved. Gotcha found while testing: `ProjectData.getFile("/")` throws
  `IllegalArgumentException: Missing file name in path` rather than returning null, so the file
  lookup has to be guarded for a folder-shaped path to reach the folder lookup.
- **Verified** live: the leftover `/scratch-*` folders are gone; a fresh `/mcp-verify/nested`
  holding an imported program reproduced the not-empty refusal, the self-descendant move refusal,
  a folder rename, and then `recursive=true` → `Deleted folder /mcp-verify (1 file(s), 1
  subfolder(s))`.

## 2026-07-09 — manage_files op=delete recursive=true — refused on programs the server itself held open
- **Task:** delete a `/scratch-*` folder holding an imported program the MCP server had already
  opened (any program tool call caches the program in `ProjectContext`).
- **Friction:** `manage_files(op=delete, recursive=true)` refused with
  `Refusing to delete /scratch-…; these files are not deletable: /scratch-…/ls — open elsewhere
  (e.g. a CodeBrowser)`. Nothing else had it open: the plugin's *own* cached handle / decompiler
  pool was the thing blocking the delete. `op=delete` on the contained file then succeeded, and
  the emptied folder deleted fine — so the single-file path worked where the folder path did not.
- **Cause:** `deleteFolder` ran its pre-flight `checkDeletable` walk (which rejects `file.isOpen()
  || file.isBusy()`) *before* anything released our handles. `deleteRecursively` did call
  `context.release(...)` per file — but only after the pre-flight had already refused, so the
  release could never run. The single-file path releases at `ManageFilesTool.java:77` before
  `deleteFile`, and `renameFolder`/`moveFolder` both call `releaseDescendants(folder)` first;
  `deleteFolder` alone did not. (The `b221d70` archive entry above claims handles are "released
  first" — true of rename/move, never of delete.)
- **Resolution** (ebbex-ghidra-mcp): hoist `releaseDescendants(folder)` above the pre-flight in
  `deleteFolder`, and drop the now-unreachable per-file `context.release(...)` in
  `deleteRecursively` so there is one release point. The pre-flight's "open elsewhere" message is
  now honest — it can only mean a *genuinely* external holder, e.g. a CodeBrowser.
- **Verified** live: imported `/bin/ls` to `/scratch-deltest`, opened it through a program tool
  (so `ProjectContext` cached it), then `recursive=true` → `Deleted folder /scratch-deltest
  (1 file(s), 0 subfolder(s))`. The non-recursive guard still refuses a non-empty folder, and the
  project returned to its original 5 files.

## 2026-07-09 — follow-ups — folder delete confirmed, a client schema-cache trap, and the DecompInterface cache question
- **`manage_files` folder delete: works.** `op=delete` on `/scratch-*` removed the empty folders,
  project back to its original 2 folders / 5 files. Nothing more needed.
- **`decompile dump_jumptables`: a client-side schema-cache artifact, not a plugin bug.** An MCP
  client that cached the tool's JSON schema at connect time stringifies a *new* parameter, and the
  server then rejects `"true"` with `/dump_jumptables: string found, boolean expected`. A client
  that re-reads the schema after the Ghidra restart calls it fine — the flag was exercised live
  against `/gog/VICEROY.EXE` the same day. **Worth keeping in mind: adding a tool argument
  mid-session may not be testable in that session.**
- **Pooled `DecompInterface` does *not* serve stale symbols — the flag does not lie.** The concern
  was that `Decompilers` reuses one `DecompInterface` per program and never calls
  `resetDecompiler()`, so the C++ side might cache symbol-scope queries and miss an override
  written after the program's first decompile. It does not:
  `DecompInterface.decompileFunction` calls `flushCache()` — which sends `flushNative` to the
  decompiler process — at the end of *every* decompile (`DecompInterface.java:832`), so the next
  decompile re-queries the symbol database. (`resetDecompiler()` restarts a dead process; it is not
  the cache-coherence mechanism.) Verified empirically on the same pooled interface, in one
  process: decompile `get_funky_string` → `decompiler-discovered (73 cases -> 13 distinct
  targets)`; write an override with `create kind=label namespace=…`; decompile again → `CONSUMED
  (16 cases -> 3 distinct targets)`. The *decompiler's own* recovered table changed, so the C++
  side plainly re-read the new symbols. **Re-confirmed independently — see the settlement below.**

## 2026-07-09 — decompile dump_jumptables — false NOT CONSUMED: segmented addresses compared as strings
Exercised the flag in a fresh session. It works, and it immediately paid for itself — but its
verdict line was wrong, and the bug is the same address-rendering trap that had by then bitten this
project three times.

- **Symptom:** `FUN_12fd_006c` decompiled with `/* WARNING: Switch is manually overridden */` and
  the correct handlers, i.e. the override was plainly consumed — while the dump printed
  `=> override at 12fd:00de: NOT CONSUMED` and separately `=> table at 1000:30ae:
  decompiler-discovered`. Those are the same address: `0x12fd0 + 0xde == 0x130ae`, and the sent XML
  even encodes `offset="0x130ae"`.
- **Cause:** `jumpTableDump` keyed its "used" map on `getSwitchAddress().toString()`. The sent
  address comes from the override symbol and renders as its own paragraph (`12fd:00de`); the
  returned one is rebuilt by the address factory and renders as the 64KB-page default
  (`1000:30ae`). `SegmentedAddress` does not override `equals`, so as *objects* they are equal
  (`GenericAddress` compares flat offset + space) — only the strings differ.
- **Fixed** in `DecompileTool.jumpTableDump` by keying on `Address` instead of its rendering
  (ebbex-ghidra-mcp `44f6082`). Re-verified: `=> override at 12fd:00de: CONSUMED (8 cases ->
  8 distinct targets)`.
- **Lesson worth generalising:** never compare segmented addresses as strings. Any tool that
  matches addresses across the Java/decompiler boundary should compare `Address`, because the two
  sides render the same flat offset differently.

### Settlement: the stale-`DecompInterface` hazard is **not** real (2026-07-09)
An earlier bullet here claimed the hazard was real and prescribed "write the override before the
program's first decompile". That contradicted the follow-up entry above, so both were tested.

- *Mechanism:* `DecompInterface.decompileFunction` ends by calling `flushCache()` whenever the
  process is `NOT_DISPOSED` (`DecompInterface.java:832`), which sends `flushNative` to the
  decompiler process. The native symbol cache is therefore empty *after every decompile*, so the
  next one must re-query the symbol database. (The `flushCache()` commented out with "we don't need
  to flush the cache" is at line 949, inside the unrelated `fillinVersionNumber`.)
- *Experiment:* fresh `/bin/ls` imported and analysed, so no prior decompile could have warmed
  anything. Decompiled `ext_wmatch` (the program's **first** decompile) — it rendered its callee as
  `FUN_001054f4`. Renamed that callee, then decompiled `ext_wmatch` again on the same pooled
  interface: both call sites now render `STALE_PROBE_written_after_first_decompile()`. A symbol
  written *after* the first decompile is visible to the next one.
- *Consequences:* there is **no** "write the override before the first decompile" rule, and
  `resetDecompiler()` is not needed for cache coherence — it restarts a dead process.
- *What most likely burned the earlier measurement:* the false `NOT CONSUMED` verdict documented
  above. Before `44f6082` the dump compared switch addresses as **strings**, so an override that
  had in fact been consumed was reported as not consumed. "Decompile, add override, decompile again
  → still not consumed" is exactly what that bug looks like from the outside, and it is the reading
  that mimics staleness. (Inference, not proven — but it fits the symptom, and staleness is now
  ruled out.)

## 2026-07-12 — manage_files delete of an MCP-imported scratch program — resolved
The 2026-07-11 entry ("cannot delete a scratch program that something still holds open")
no longer reproduces: a full MCP-driven import → analyze → delete cycle on
`/scratch-feedback-test/ls` now completes cleanly, with no GUI click needed. Two
hardening changes landed with the retest:

- **Errors now say who is blocking.** `op=delete` on an open file reports
  `held open by: <consumer names>` (via `DomainFile.getConsumers()`) instead of the
  generic "open elsewhere (e.g. a CodeBrowser)", so the next occurrence of the original
  symptom will identify the holder instead of leaving it a mystery. A busy file
  (background task mid-run) gets its own message.
- **Delete during background analysis is refused, not raced.** The old order released
  our cached handle *before* checking the file's state; releasing the last consumer
  mid-analysis would close the program under the running analyzer. All destructive
  `manage_files` ops now check `isBusy()` first and refuse with "wait and retry"
  (verified live: delete during `analyze` of `/bin/ls` refuses, succeeds after).
  `ProjectContext.release` also drops cache entries reachable under a variant path
  spelling, not just the exact string.

## 2026-07-12 — create/clear kind=reference — resolved
The "no tool to create references" entry (hand-applying the 1d1d:19c0 jump-table
override needed a program-wide one-shot analyzer run just to materialize 8 refs).
`create kind=reference` adds a memory reference (`address` → `to_address`,
`ref_type` enum of jump/call/read/write/data/indirection variants, optional
`operand_index`, default mnemonic), and `clear kind=reference` removes it — both
batchable since create dispatches from `batch`. Verified live on `/test/VICEROY.EXE`:
create → shows in `xrefs` as `[COMPUTED_JUMP computed]` → clear → repeat clear errors
"No reference from …".

## 2026-07-12 — search_memory kind=instruction — resolved
The "no instruction-level search" gap from viceroy's workflow doc (the legacy bridge
could search `JMP` + `CS:[BX`; `search_memory` required hand-assembled opcode bytes).
`search_memory kind=instruction` matches disassembled instruction text
case-insensitively with whitespace collapsed, echoing the full matched instruction per
hit. Verified live on `/VICEROY.EXE`: pattern `JMP word ptr CS:` returns the overlay
dispatch sites (`112b:000f JMP word ptr CS:[BX + 0x14] in FUN_112b_0002+0xd`, …) with
the usual paging footer. Only already-disassembled instructions match (the no-match
footer says so and points at kind=bytes).

## 2026-07-12 — GET /version readiness + build probe — resolves the startup-wait entry's server half
The 2026-07-11 entry ("no MCP-native way to wait for Ghidra startup") wanted a clean
readiness signal instead of shell-polling `…/mcp/program` for an error-shaped HTTP 400.
The server now exposes `GET /version` (plain HTTP, no MCP handshake): one poll answers
readiness *and* identity, returning the build stamp
(`MCPServer 0.2.0 (git f06c42b, built 2026-07-12 10:44:41 UTC)` — semantic version from
`version.properties`, git commit with `+dirty` marker, UTC build time). Motivated the
same day by a port-bind race where a second Ghidra instance held 8765 with an unknown
build and the "MCP up" probe couldn't tell instances apart. The entry's other half — a
wait-for-console-pattern parameter on `launchConfiguration` — belongs to the eclipse
MCP server, not this repo, so it leaves this log with that pointer.

## 2026-07-12 — the three gaps flagged in viceroy's workflow doc — all three closed
The "Known gaps flagged in viceroy's workflow doc" entry named three items collected from
`../viceroy/docs/ghidra-workflow.md` that had never been filed or confirmed. All three are
now resolved, two with code and one by measurement.

### Masked/wildcard byte search in overlay spaces — works; the old bridge's flakiness is not ours
Never re-verified after the move off the python bridge, where only exact patterns were
trustworthy. Tested live on `/VICEROY.EXE`: `search_memory kind=bytes` with `??` wildcards
resolves inside overlay spaces and masks correctly.
- `c8 16 00 00 56 8b ?? 42 85` → `OVERLAY_00::010000`, `OVERLAY_13::010000` (the two pages
  genuinely hold identical code), and the unmasked pattern returns the same set — the mask is
  neither dropping hits nor inventing them.
- `c8 ?? 00 00 56 8b` → many more hits across resident code, so the mask genuinely widens the
  match rather than being ignored.
**No code change.** Wildcard search is trustworthy, in overlay spaces included.

### No instruction-level search → `search_memory kind=instruction`
(Also recorded above.) Resolved the same day.

### No script-execution tool → not added; the concrete need is met by `list user_only`
The gap was hit for real as "the mandated `ghidra_symbols.md` refresh needs
`ghidra_dump_symbols.py` from the GUI Script Manager". That need is a **symbol dump**, not
arbitrary scripting, so it does not justify a script-execution tool — which is precisely the
capability whose absence this server's whole thesis defends (a `run_script_inline` re-creates
the unbounded surface the small-tool-set bet exists to avoid, and it is how the legacy bridge
invited the DB-surgery accidents catalogued in viceroy's playbooks).
`list` instead gained **`user_only`** (kind=functions|symbols|data), which drops names Ghidra
generated (`SourceType.DEFAULT`: `FUN_*`, `LAB_*`, `DAT_*`) and keeps the ones a human or an
analyzer chose. Verified live: `/VICEROY.EXE` reports **1225 curated functions of 2773**, i.e.
exactly the symbol map the script produced, over MCP, paginated.
**The design decision stands: no script execution.** If a future need genuinely requires
arbitrary code (not an export), file it fresh — that would be new evidence, not this entry.

### No bulk documentation migration → the `migrate` tool
The legacy bridge's `merge_program_documentation` had no equivalent, which left a re-import
of `/VICEROY.EXE` (needed to pick up the fixed CS-resolution analyzer) blocked on "it loses
hand-added names/types unless migrated". `migrate` copies function names, signatures, comments,
labels, data types and defined data from another project DB, with `dry_run` and per-`kinds`
selection. Both documented legacy gotchas are designed out rather than reproduced — and the
first live dry run proved the design mattered:

- **Gotcha 1 (it clobbered better names).** The legacy tool renamed a target function to the
  source's name whenever the two differed, dragging 157 correctly-named overlay stubs back to
  their old naive names. Root cause here: a *placeholder* name carries no information. `migrate`
  never copies one from the source and never lets one protect a target
  (`placeholder_pattern`, default covering `FUN_`/`LAB_`/`DAT_`/`caseD_`/`switchD_` **plus
  address-spelled analyzer names like `OVL01_0000` / `OVLSTUB_20_0718`**). The stale
  `OVLSTUB_*` names in the old DB are placeholders, so they simply cannot overwrite the
  re-import's correct ones. `on_conflict=skip_named` (default) then only arbitrates genuine
  meaningful-vs-meaningful disagreements, and lists them for review;
  `on_conflict=overwrite` lets the source win.
- **This is worth dwelling on:** the first implementation judged "is this a real name?" by
  `SourceType != DEFAULT`, which *looked* right and passed review. The live dry run against
  `/VICEROY.OLD` → `/VICEROY.EXE` showed it silently refusing to migrate **449** of the best
  human names, because the RTLink analyzer assigns `OVL01_0000` at `ANALYSIS` source and that
  counted as "already named". Judging names by *meaning* rather than by *who assigned them*
  took it to **955 applied, 0 wrongly kept**. A dry run on real data caught what reading the
  code did not.
- **Gotcha 2 (source-only functions skipped in silence).** Names land only where the target has
  a function at the same entry; the legacy tool dropped the rest without a word, which is why
  its dry-run counts were optimistic (planned 1310, applied 1279). `migrate` counts and lists
  them under **SOURCE-ONLY** — the live run names all 41 (the FAB decompressor family at 20a5,
  the printf helpers at 1d1d, the OVERLAY_19 terrain-drawing family, …) so the caller knows
  exactly what to re-create (`create kind=function` with `end_address`) before re-running.

Write path verified end-to-end on a throwaway pair (`/bin/ls` imported twice, analyzed, one
function renamed + plate-commented in the source): migrate applied exactly those two changes
and nothing else; a meaningful target name then survived `skip_named` (and was reported) and
fell to `overwrite`. The live `/VICEROY.EXE` was never written — the re-import remains the
user's decision, and `migrate --dry_run` now tells them exactly what it would cost.

## 2026-07-12 — migrate destroyed 86 instructions on its first real run — fixed (0.3.2)
The `migrate` tool's first run against the real `/VICEROY.EXE` **overwrote code with data**. Worth
recording in full, because the bug was invisible in review and in the obvious test.

- **Symptom.** After migrating from `/VICEROY.OLD`, `OVLSTUB_30_0608` had 14 callers where it had
  15 before. At `1000:0048` a `CALLF OVLSTUB_30_0608` had become `uint = 2C9Ah`.
- **Cause.** `Listing.getDefinedDataAt(addr)` returns **null when an instruction occupies the
  address** — it answers "is there defined *data* here?", not "is anything here?". The
  "nothing here, safe to write" check was written against it, so every address holding *code*
  looked empty; the applier then called `clearCodeUnits` and laid the source's data over the
  instruction, taking its references with it.
- **Why it fired where it hurts most.** The source is an *older* analysis. It holds data exactly
  where the current analyzer has since correctly recovered code — so the bug triggers precisely
  on the sites where the new analysis is *better* than the old one. The re-run with the fix
  reports **86 such addresses**, so the first run destroyed up to 86 instructions, not one.
- **Fix (0.3.2).** Ask the listing for the **code unit** (`getInstructionContaining`), not just
  defined data, and refuse to write wherever the target holds an instruction — or wherever one
  falls inside the new type's extent. This holds even under `on_conflict=overwrite`: that flag
  arbitrates *documentation*, it does not license undoing disassembly. Refusals are now listed in
  a loud `DATA REFUSED` section instead of being counted silently, so a genuine data site can be
  cleared deliberately (`clear kind=code`) and re-migrated.
- **Why the tests missed it.** The write path was verified on a *scratch pair*: `/bin/ls`
  imported twice and analyzed identically. Two identical fresh analyses never disagree about
  code-vs-data, so the only case that mattered was the one the test could not produce. The
  dry run also *did* say "310 data applied" — it was read as harmless gap-filling; nobody asked
  what those 310 were replacing. **A migration test is only meaningful when source and target
  disagree**, which is the whole reason a migration exists.
- **Recovery.** The DB was a fresh import plus an analyzer pass (no hand work), so it was deleted,
  re-imported, re-analyzed, and re-migrated with the fix. Verified afterwards: `1000:0048` is an
  instruction again, the stub is back to 15 callers, 2773 functions, and the documentation landed
  (955 names, 8853 comments, 363 labels, 56 signatures, 54 data types, 223 data).
  Had there been hand work, the only clean revert would have been Ghidra's in-memory **undo**
  (Ctrl+Z on the single `Migrate documentation from …` transaction) — and it must happen *before*
  Ghidra restarts, because the undo stack does not survive a restart, and the endpoint's auto-save
  had already written the damage to disk. **There is no MCP undo tool; that is a real gap this
  incident exposed** (see the open log).

## 2026-07-12 — "no undo over MCP" — resolved, but NOT with undo: Ghidra has no undo to expose
Filed the same day (after `migrate` destroyed 86 instructions) asking for a `save op=undo`. Built
it — every mutating call is already exactly one named Ghidra transaction, so `Program.undo()`
looked like a two-hour win. **It cannot work, and the entry's whole premise was wrong.**

- **Ghidra discards its undo history on every save.** Two independent mechanisms:
  `BufferMgr.doSetSourceFile` (the last thing every `BufferMgr.save` does) calls `setMaxUndos(0)`
  to "pack all versions into baseline checkpoint", and `ProgramDBChangeSet.clearUndo()` runs on
  save as well. This server **auto-saves after every mutating tool call** (deliberately — see the
  bounded-deferring-save entry), so the undo stack is empty before any *next* call could use it.
  Verified live: two committed `set_comment` calls, then `getAllUndoNames()` → empty, both stacks.
- **The advice given during the incident was therefore wrong.** The user was told to press Ctrl+Z
  in the CodeBrowser before restarting Ghidra, on the theory that the undo stack was in memory and
  perishable. It was not perishable — it was already *gone*, cleared by the auto-save that ran when
  the `migrate` call returned. Ghidra's GUI Undo would have had nothing to offer either. The user's
  own instinct — delete the DB and re-import — was the only thing that could have worked.
- **The lesson generalises beyond undo:** "each tool call is one transaction, so it must be
  undoable" is a plausible chain of reasoning that is simply false in this architecture. The
  auto-save that makes edits durable is exactly what makes them irreversible.

**What replaces it (0.4.0):** a snapshot taken *before* the write — which, unlike undo, also
survives a Ghidra restart.
- `manage_files op=copy` duplicates a file into a folder (optionally renaming): the snapshot and
  restore primitive. Restore = delete the damaged file, copy the backup back, rename it.
- `migrate` now snapshots the target automatically to `/backups/<name>.pre-migrate-<stamp>` before
  writing (opt out with `snapshot=false`) and reports the path with the restore recipe — the
  incident is precisely the case where nobody thinks to ask for a backup first.

Verified end-to-end on `/gog/VICEROY.EXE`: snapshot; clear the code at `entry` (210d:071d), which
auto-saves and drops the function's 3 outgoing refs; delete + copy the backup back + rename; the
refs are back at 3. Damage that undo could never have reached, recovered from disk.

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
- **Not a plugin fix.** Ghidra never creates a reference from a 16-bit DS-relative
  operand, so there is nothing for `xrefs`/`inspect` to report — no tool change here can
  surface what the reference manager does not hold. The fix belongs in the fork's
  reference analysis (the constant-propagation / RTLink analyzers that already know
  DS=DGROUP).

**Resolved 2026-07-12 — in the fork, as predicted.** Two passes in the fork's
`RTLinkXrefAnalyzer` (branch `rtlink`) now populate the reference manager, so
`xrefs`/`inspect` answer directly:
- The **deref pass** (already present when the entry was filed) creates READ/WRITE refs
  for DS-relative memory operands (`MOV AX,[0x540e]`) — 10,289 refs on VICEROY.EXE.
- The **address-of pass** (new; commits "RTLink: materialize address-of immediates as
  DATA xrefs", the ADD extension, and "suppress segment and sentinel constants")
  covers the entry's exact case: `PUSH imm16`, `MOV BX/SI/DI,imm16`, and
  `ADD AX/BX/CX/DX/SI/DI,imm16` whose immediate lands in a mapped non-executable
  DGROUP block gets a `RefType.DATA` ref — **350 refs** on VICEROY.EXE. Two earlier
  states of this note were wrong in opposite directions. The first cut (PUSH/MOV
  only, 269 refs) had a **recall** hole: it found 2 of `g_players`' 29 real
  referents, because for an array-typed global the dominant shape is the indexing
  idiom — `&g_players[i]` compiles to a scaled index plus `ADD reg,0x540e` (27 of
  29 sites). The second cut (with ADD, 371 refs) had a **precision** hole: ~21 of
  371 refs were bogus — 0xA000, the VGA segment, lands above the data-block start,
  so all 20 of its occurrences (far-pointer segment halves, `MOV ES` loads, one
  post-branch ADD) minted a fake `DAT_2b5a_a000` with 20 xrefs, plus one
  `PUSH 0x8000` (high half of a 32-bit INT_MIN). Each commit had audited only its
  own increment; the combined pass was never re-measured. Now suppressed by two
  documented value exclusions (video segments A000/B000/B800; the 0x8000 sentinel)
  and a shallow flows-into-segment-register check. **Combined audit over all
  shapes: 350 created, 2 known false positives (crt_rand's LCG addend 0x9EC3, a
  0xC000 bitmask) → ~99.4% precision; recall 29/29 on the g_players probe.**
- **Measurement traps, both hit here.** (1) A headline count is not an accuracy
  measure: "269 created" said nothing about the 27 missed, "371 created" nothing
  about the 21 wrong — report precision and recall separately, against enumerated
  ground truth. (2) `search_memory kind=instruction` matches the raw operand text,
  and PUSH renders imm16 ≥ 0x8000 as *negative* — `PUSH 0xa000` prints and matches
  as `PUSH -0x6000`, so value probes silently miss the upper half of the immediate
  range (exactly how the 0xA000 cluster escaped the first audit). Enumerate
  `PUSH -0x` too, or byte-search the encoding. Ground truth for one global:
  `search_memory kind=instruction pattern="0x<offset>"` (plus the negative form
  when offset ≥ 0x8000).
- **Structural caveat the original task should know:** `g_savegame_head` (5370)
  legitimately stays at "Xrefs: 0 to" — no instruction in the program contains 0x5370
  in any operand; code addresses its *fields* directly (`g_game_year` @538a has 45
  refs). For such base labels, zero really does mean "no direct references", and the
  field labels are where the refs live.
