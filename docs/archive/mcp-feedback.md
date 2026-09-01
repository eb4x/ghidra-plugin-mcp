# ghidra-plugin-mcp — Dogfooding Feedback (Archive)

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

## 2026-07-13 — three entries from the husk hunt — all fixed (0.5.0)
Filed by the agent chasing the 1-byte-husk bug in the fork. All three cost it real time, and all
three are the same failure: **a tool that silently omits what it could not do teaches the caller
something false.**

- **`list kind=bookmarks`** (and bookmarks in `inspect`). The disassembler records its own failures
  as ERROR bookmarks ("Bad Instruction"), the program's account of what it could not decode — and
  nothing exposed them. The agent instead patched `Msg.debug` probes into Ghidra's `Disassembler`
  through Eclipse and re-ran the import **five times**, where `filter=error` would have answered it
  in one call.
- **`list kind=functions` body size + `min_body`/`max_body`.** Lines now carry `[N callers, 261B]`,
  and a function whose entry holds no instruction is flagged `<-- HUSK: no code at entry`.
  Measuring the blast radius otherwise meant ~2800 `inspect` calls; the agent ended up building the
  counter into the fork's analyzer and reading it from the log. `max_body=1` now answers it directly.
- **`disassemble` announces undefined bytes.** It silently began at the *next* instruction when the
  requested address held undefined bytes, which reads as "looked there, found nothing" when those
  bytes were never examined. It now prefixes a NOTE naming what is actually there (undefined /
  offcut / defined data), how far the gap runs, and that the listing **skips** the requested
  address. **This misreading sent both the agent and the reviewing session down a wrong first
  theory** — the most valuable of the three.

**The outcome that justifies the log.** The husk bug these entries came from was itself found by
`migrate`'s new body-mismatch report (0.4.1), which exists because the *previous* round of
dogfooding showed migrate silently applying documentation across mismatched bodies. A routine dry
run then reported **363 husks** — functions with no code at all, including `fwrite` (44 callers) —
where the project's own notes had estimated "3 of ~604". The fork fixed it (a core Ghidra
`Disassembler` deferred-call-flow bug plus RTLink repair passes); a fresh import now reports **0
husks**, body mismatches fall 420 → 65, and the map renderer (`draw_map_tile` + 14 functions,
~2.3 KB) exists for the first time. Every step of that chain was a tool being made to say what it
had glossed over.

## 2026-07-13 — list kind=bookmarks filter=error — the ERROR channel was 100% false positives
- **Task:** Trust `list kind=bookmarks filter=error` (new in 0.5.0, the entry above) as the "what
  could the disassembler not decode" channel. A fresh VICEROY.EXE import reported 541-ish ERROR
  bookmarks; every one was a fossil, so the channel said "541 things are broken" on a DB where
  nothing was.
- **Finding:** All of them sat in the two RTLink stub segments (281f/CODE_99, 2a1f/CODE_100), on
  dispatch stubs that `RTLinkOverlayAnalyzer` had in fact resolved. A stub's `JMPF 0000:offset`
  only becomes valid when the overlay manager patches it at run time, so any disassembly of it
  records "Could not follow disassembly flow into non-existing memory". The analyzer then
  relocates and thunks the stub, but never removed the mark it had invalidated.
- **Correction to the original diagnosis:** the mark is not left over from an *earlier* pass.
  `RTLinkOverlayAnalyzer` runs at `FORMAT_ANALYSIS.after()` (it has to — it creates the overlay
  blocks everything else depends on), so on a fresh import it resolves each stub *before* the
  disassembler ever walks into it: the marks are stamped **after** the analyzer is done, and are
  stale the moment they are written. Clearing at resolve time alone fixes only the
  retrofit/one-shot path (540 → 2 on a re-run) and does nothing on a fresh import.
- **Fix (fork `rtlink`, RTLinkOverlayAnalyzer — not the plugin):** `createThunkAtStub()` now
  reports whether the stub is really resolved; resolved stub bodies are cleared *and recorded*,
  and swept again in `analysisEnded()`, once every other analyzer has run. Stubs whose resolution
  genuinely failed keep their mark and their log line.
- **Measured:** fresh import + full analysis, ERROR bookmarks **540 → 2** (analyzer logs "Cleared
  538 stale Bad Instruction bookmark(s)"). Both survivors are real: `281f:0f71` (a CALLF+JMPF pair
  whose CALLF does not target a discovered dispatcher, so it is not a dispatch stub and stays
  unresolved) and `275d:0778` ("Maximum run of repeated byte instructions exceeded" — a run of 00
  bytes walked as code). No regressions: 2793 functions, 611 stubs + 370 trampolines resolved, 29
  xrefs to `2b5a:540e`, 3 one-byte functions (all real, no husks).
- **Takeaway:** `filter=error` now means something on VICEROY — worth re-checking after any
  analyzer change, since a diagnostic channel that is all noise is worse than none. The channel the
  three husk entries won was only worth having once the thing writing to it stopped lying.

## 2026-07-14 — xrefs / clear — no way to ask "which references come *from* this range?" — fixed (0.6.0)
- **Task:** Delete every reference **from** the RTLink runtime (`210d`, `275d`) **into** DGROUP —
  the ones an over-broad `DS` assumption had invented. A bounded, well-defined set: one
  from-range, one to-range. It took ~1500 calls.
- **Friction:** `xrefs direction=from` took a *location*, so on a function it returned only the
  refs from the **entry address**, not from the body — references are recorded on the instruction
  that makes them. There was no from-range query at all, so "refs out of segment 210d" was not
  askable; the agent inverted it (1043 `direction=to` calls over every DGROUP symbol to find 437
  references), then spent 437 more single-pair `clear kind=reference` calls, because `batch`'s
  `op` enum had no `clear`.
- **Fix:** `xrefs` now takes exactly one of three targets — `location` (a point, as before),
  `function` (its **whole body**), or `min_address`/`max_address` (an explicit range, e.g. a whole
  segment) — plus a `filter` that constrains the *other* endpoint (`filter='2b5a:'` for refs
  landing in DGROUP). Range results name **both** endpoints, so the output is directly consumable
  as `(address, to_address)` pairs. `clear` joined the `batch` edit tools, so those pairs go back
  in one call. The two-space range case (an overlay/segment straddle) is rejected with the tool's
  own message rather than Ghidra's raw `AddressSet` exception.
- **Measured (smoke, /bin/ls):** `xrefs function=_init direction=from` returns the 4 body
  references a point query missed entirely; a range query over `00100000-00140000` with
  `filter=CALL` returns 1453, paginated; `batch op=clear kind=reference` deletes them. The whole
  original task is now two calls instead of ~1500.
- **Not done:** a *ranged* destructive `clear` (delete every ref from range X into range Y) was
  deliberately left out — with no undo, a one-call bulk delete of an unenumerated set is the wrong
  shape. Enumerate with `xrefs`, look at what you got, then hand the explicit pairs to `batch`.
- **Left open:** the entry's "bonus hazard" — a typed region (`savegame_unit[300]`) absorbs the
  interior `DAT_` labels, so a label-based audit silently misses references that still exist, and
  `list kind=symbols` gives no hint. The from-range query makes the reference-based audit possible,
  which is the real answer, but the label-absorption trap itself is unguarded.

## 2026-07-14 — migrate — `signatures` silently dropped custom storage, decompiling WRONG — fixed (0.7.0)
- **Task:** Carry RE work across a re-import with `migrate`. The question was what it actually
  preserves.
- **Friction:** `signatures` round-tripped through the **C prototype only**
  (`FunctionDefinitionDataType` + `ApplyFunctionSignatureCmd`), so any signature pinned with
  `set_function_signature`'s `parameters[].storage` / `return.storage` came back re-derived from
  Ghidra's default calling convention — and decompiled **wrong** without any error. `fseek`
  (`1d1d:0a3e`), pinned `offset@Stack[0x6]` because MSC pushes an unaligned `long`, came back at
  `Stack[0x8]`, and the body reverted to `if (0x2ffff < offset)` instead of `if (2 < origin)`.
  18–55 of VICEROY's signatures are custom-storage; all regressed silently.
- **Fix:** the signature path now checks `hasCustomVariableStorage()`. For those functions it
  carries the exact storage across DBs — `VariableStorage.getSerializationString()` (the same
  program-relative encoding Ghidra persists) deserialized into the target, applied with
  `updateFunction(… CUSTOM_STORAGE)` — instead of the prototype path. The report counts them
  (`163 applied (55 with custom register/stack storage carried verbatim)`), and any it genuinely
  cannot reconstruct are listed by name under **CUSTOM STORAGE NOT CARRIED** rather than downgraded
  in silence. Prototype-only signatures keep the `ApplyFunctionSignatureCmd` path.
- **Verified live (0.7.0):** copied VICEROY, broke `fseek` to a plain C prototype (`offset` slid to
  `Stack[0x8]`, `origin` to `Stack[0xc]`), migrated signatures back from the good DB → `offset`
  restored to `Stack[0x6]`, `origin` to `Stack[0xa]`, and `fseek` decompiled `if (2 < origin)` with
  `offset`/`origin` passed correctly to `lseek`. 55 signatures reported as custom-storage carried.
- **Not done:** `migrate` still has no `context` kind (register-context is its own open entry) — the
  custom-storage fix is orthogonal to that.

## 2026-07-14 — `calls`/`xrefs` — callers hidden behind a same-named thunk gate — fixed (0.7.0)
- **Task:** Find who calls `draw_colony_sprite` (`112b:0c64`), a resident function the overlays reach
  through a far-call gate in segment `281f`.
- **Friction:** the thunk carries its target's name, so both tools dead-ended confusingly.
  `calls kind=callers draw_colony_sprite` → `281f:02a8 draw_colony_sprite` (reads as "called by
  itself"); `xrefs direction=to` showed a ref `in draw_colony_sprite+5` with nothing saying it was a
  thunk. The five real callers only surfaced after `inspect`-ing the address to discover the thunk,
  then re-running `xrefs` on the thunk's own address. Hits nearly every cross-overlay call chain.
- **Fix:** `calls kind=callers` now resolves *through* thunk gates — a caller that is a thunk to the
  queried function is replaced by *its* callers (through chains), each marked `(via thunk … @ addr)`;
  a gate with no callers of its own is surfaced, not dropped. Thunk callees are annotated with their
  ultimate target, and `xrefs` names any endpoint that lies in a thunk `(thunk -> target @ addr)`.
- **Verified live (0.7.0):** `calls kind=callers draw_colony_sprite` returns exactly the five overlay
  callers the plate comment names (`draw_colonies_on_map`, `report_sons_of_liberty`,
  `report_colony_defenses`, `draw_side_info_panel`, `combat_show_analysis_dialog`), each
  `(via thunk draw_colony_sprite @ 281f:02a8)`.
- **Was not the same as** the 2026-07-16 `OVLSTUB_*` entry, which at the time had no thunk
  relationship to follow: those RTLink dispatch stubs were not Ghidra thunk functions, so this fix
  did not reach them. Superseded on 2026-07-25 — the analyzer now makes them real thunks, and this
  fix is exactly what resolves them through it. See that entry, archived below.

## 2026-07-25 — no project lifecycle tools — a moved project dir stranded the session — fixed (0.8.0)
- **Task:** Decompile `tile_prime_resource` (137f:04b0). Never got to make the call: the instance had
  opened its project at `/home/erikberg/src/viceroy`, which was renamed to `viceroy-old` the next day.
- **Friction:** `list_files` and `get_application_info` kept answering confidently from
  `ProjectData`'s in-memory cache — including a `Location:` that no longer existed — while every tool
  that reads file *contents* failed with a raw `…/idata/12/~0000012b.db/db.832.gbf (No such file or
  directory)`. Nothing on the application-level surface could re-point the instance, and restarting
  reopened the same stale locator.
- **Fix:** `manage_project` with `op=open|close|list_recent` (one tool, not the three the entry asked
  for), plus the two diagnostics the entry rightly wanted taken first:
  - `get_application_info` now verifies the locator and flags `Location: … [UNREACHABLE — …]`, saying
    outright that cached listings still work but no content can be read.
  - every program tool's open failure leads with the cause and the fix instead of the `.gbf` path.
  - `op=open` refuses while another project is open **and reachable**, but replaces an unreachable
    one — the entry's own suggestion (refuse whenever a project is open) would not have unblocked the
    session that logged it, because a stale project *was* open.
  - `op=close` refuses while anything is busy or unsaved (`on_dirty=save|discard` to override), and
    calls `setLastOpenedProject(null)` so a restart no longer reopens what you just closed.
- **The two things that were nearly wrong.** (1) Cache release has to happen *before*
  `Project.close()`: `DefaultProjectData.close()` defers its `dispose()` while any domain object is
  still open, and the `.lock` release lives only in `dispose()` — so releasing afterwards leaves a
  closed project holding its lock, unopenable. (2) `close()` + `setActiveProject(null)` is an
  *incomplete* close. Ghidra fires `projectClosed` to its project listeners in between (see
  `FileActionManager`'s delete-project branch), and skipping it fails only on the **next** open, where
  `RecoverySnapshotMgrPlugin` throws "Unexpected - two or more projects active". Caught live, not by
  reading: the first open→close→open cycle failed exactly there.
- **Verified live (0.8.0):** from a cold no-project state, `op=list_recent` listed the recent projects
  (the one thing that was previously a dead end), `op=open` opened `viceroy-old/viceroy` in 72ms with
  all 15 files, `op=close` released the `.lock` file, and open→close→open→close cycled cleanly with no
  listener errors in the log. Refusals all fire: missing `name`, blank `path` (which would silently
  mean Ghidra's temp dir), a nonexistent project, the old moved-away path, and switching away from a
  healthy project. Headless refusals verified by `smokeTest`.
- **Not done:** `on_dirty=save`/`discard` and the busy/dirty refusals are verified by construction
  only — making a file *stay* dirty is hard when the server auto-saves every call, and forcing the
  busy path meant running analysis on a curated RE project. Also out of scope: `Transactions.modify`
  still uses an unbounded `invokeAndWait`, so a modal dialog on the EDT hangs every mutating program
  tool. `manage_project`'s own EDT hops are bounded; that one is not, and it is the remaining reason a
  dialog can wedge the server.

## 2026-07-16 — `decompile`/`calls` — RTLink overlay stubs severed the call graph — fixed in the analyzer
- **Task:** VICEROY.EXE UI geometry RE. `decompile`/`calls` on overlay dispatch thunks such as
  `OVLSTUB_20_0EB0` should have pointed at the real target function inside the overlay.
- **Friction:** every stub decompiled to the same opaque `rtlink_smart_vector_dispatch(0x281f);
  halt_baddata();` with a "Bad instruction / Truncating control flow" warning, and no reference tied
  the stub to its target — the call graph was severed at every overlay boundary. The workaround was
  pure manual arithmetic on the stub *name*: `OVLSTUB_<NN>_<OFFS>` → `OVERLAY_<NN>::03a000 + 0xOFFS`,
  for every stub, and it only worked because an earlier analyst had named them consistently.
- **Fix: not in this repo.** `RTLinkOverlayAnalyzer.createThunkAtStub` (now in the standalone
  `ghidra-plugin-rtlink` extension) makes each stub a real Ghidra **thunk** of its overlay target —
  refusing to plant a husk when the target never became code, stamping `__cdecl16far` so far call
  sites decode their stack args, clearing the stale no-return flag that truncated every caller, and
  sweeping the stub's own ERROR/WARNING bookmarks. The plugin side already met it halfway in 0.7.0:
  `calls` annotates a thunk callee with its ultimate target and follows gates back to real callers.
  So the suggested `resolve_overlay_stub` tool and the documented naming rule are both moot — nothing
  depends on the stub's name any more.
- **Verified live (0.8.0 / rtlink 0.3.0):** `inspect OVLSTUB_20_0EB0` reports
  `thunk → draw_map_view (OVERLAY_20::03aeb0)` and `calls kind=callees` names
  `OVERLAY_20::03aeb0 draw_map_view` — the address the entry had to compute by hand.
- **Still open:** the entry's *second* item. Nothing warns that a function's prototype is a guess, so
  16-bit register-args render as invented `in_AX`/`in_DX`/`in_BX` locals and mis-order the stack args
  while looking plausible. That one is an MCP-side ask and stays in the open log.

## 2026-07-16 — `decompile` — nothing warned that a prototype was a guess — fixed (0.8.1)
- **Task:** VICEROY.EXE UI geometry RE. (This was the second item of the overlay-stub entry archived
  above; the two were split when the first half was resolved in the analyzer.)
- **Friction:** 16-bit real-mode functions pass args in AX/DX/BX as well as on the stack. With no
  committed prototype the decompiler invents one, rendering the register args as bogus
  `in_AX`/`in_DX`/`in_BX` locals and silently mis-ordering the stack args around them.
  `surface_fill_rect` appeared to take `(color, h, desc...)` with no x/y at all. The output reads
  perfectly plausibly and is wrong, and nothing marked it — `set_function_signature` with
  `parameters[].storage` fixes it beautifully once you know, but nothing tells you there is anything
  to know.
- **Fix:** two independent signals on the `decompile` header.
  - Every header now ends `prototype guessed` or `prototype committed`. The discriminator is exactly
    the one the decompiler itself uses — `SourceType.DEFAULT`, per
    `FunctionPrototype.grabFromFunction`, which sets neither `outputlock` nor `voidinputlock` for a
    DEFAULT signature and so lets the decompiler derive its own. Deliberately *not* "DEFAULT or
    ANALYSIS": an analyzer-applied signature (FID, demangler) does lock the prototype, and calling
    that a guess would cry wolf on every library match.
  - A ⚠ UNDECLARED INPUTS line names the inputs the decompiler read but could not place in the
    prototype, with their storage. These are the decompiler core's "irregular inputs"
    (`database.cc`), rendered `in_<REG>` or `in_<space>_<offset>` for an undeclared *stack* arg;
    detection is by the `in_` prefix, matching what Ghidra's own
    `FindPotentialDecompilerProblems` and `DecompilerParameterIdCmd` do, and excluding
    `in_FS_OFFSET` for the same reason they do.
  - The two are orthogonal on purpose. An `in_AX` on a *committed* prototype is the more alarming
    case — the signature is incomplete and its author believed they were finished — so the wording
    changes to say so.
- **How bad it actually was.** The entry cited one function; measuring it found **7 of a 12-function
  sample** carrying undeclared inputs, including `draw_unit_icon_with_badge` (1483 bytes),
  `draw_village_sprite` (1234) and `draw_colony_sprite` (594) — all three of which take their
  coordinates in registers and were being rendered without them. The clean five were small
  math/predicate helpers. So this was the normal state of an uncommitted 16-bit function here, not an
  edge case, which is also why the warning is two lines rather than four: at that incidence a longer
  block costs more than it teaches on every batch decompile, and the reasoning lives in the tool
  description where it is paid for once.
- **Verified live (0.8.1):** `screen_present_rect` → `prototype guessed` + `in_AX (AX:2)`;
  `font_draw_string` → all three of `in_AX, in_BX, in_DX`; `surface_fill_rect` → `prototype
  committed`, no warning, which is the regression check that the entry's own fix still holds;
  `tile_unit_owner`/`crt_aFldiv` → `guessed` with no warning (invented *stack* params only, so no
  false positive); and the x86-64 smoke target's `main` → `guessed`, no warning, confirming the
  warning does not fire on a target whose args the decompiler models correctly.
- **Not done:** nothing flags an invented *stack* parameter list on its own — `tile_unit_owner`
  renders `(param_1, param_2)` from a `(void)` listing signature and only says `prototype guessed`.
  That is the right call for now (it is most of the program, and usually right), but it means
  "guessed" is doing real work in that header and should not be read as cosmetic.

## 2026-07-25 — `Transactions.modify` — an unbounded EDT wait could hang every write — fixed (0.8.2)
- **Task:** logged while building `manage_project` (0.8.0), which bounded its own event-thread hops
  and so left the server with two different EDT policies — the tool I had just written, and every
  write tool, which still used a bare unbounded `SwingUtilities.invokeAndWait`.
- **Friction:** Ghidra raises *modal* dialogs from paths an agent can provoke (a program-upgrade
  prompt, a recovery-snapshot question, an error dialog), and a modal dialog pumps a nested event
  loop, so the event thread never returns to our runnable. Every mutating program tool then blocked
  indefinitely — no error, no timeout, nothing saying a human had to click something. The MCP client
  simply hung.
- **Fix:** extracted the bounded marshaller into `util/Edt.runNow(Callable, timeoutMs)` — one EDT
  policy for the server rather than two — and put `Transactions.modify` on it. `manage_project`'s
  private copy is gone, and its open/close timeout messages now build on the shared
  `Edt.timeoutAdvice`. Bounds: 60s for a single edit (absurdly generous next to the milliseconds one
  takes; the point is to report a wedged event thread, not to police slow work) and 600s for
  `migrate`, which is thousands of edits in one transaction and would otherwise report a timeout on
  a migration that is merely still working. `analyze` was never affected — it runs its own
  transaction off this path.
- **What a timeout cannot do is cancel.** The task may be mid-transaction, and abandoning it
  half-done would be worse than reporting it, so it runs to completion once the event thread frees.
  A timeout therefore means *unknown outcome*, and the message says so — including that the edit, if
  it did land, is only in memory until `save`.
- **Verified by forcing the branch**, not by reasoning about it: temporarily setting the bound to 1ms
  and running `smokeTest` produced the timeout result from five write tools and, notably, made
  `batch`'s next edit fail with `IOException: Unable to lock due to active transaction` — because the
  timed-out transaction is still open and still holds Ghidra's write lock. That cascade is now named
  in the timeout message, since an agent would otherwise read each lock error as a fresh mystery
  instead of as this timeout unwinding. Restored to 60s, `smokeTest` is green (it exercises every
  write tool, and the bounded path works headless as well as under the GUI). Live check on a
  throwaway import in a real GUI Ghidra: `rename` then `set_comment` both applied and read back,
  then the scratch folder was deleted — the RE project was never written to.
- **Not done:** the policy is uniform for tool-driven writes, but `Edt.runNow` is only as good as the
  bound each caller picks, and a wedged event thread still freezes Ghidra's own UI. This makes the
  server survive a modal dialog; it does not make the dialog go away.

## 2026-07-14 — `read_bytes` — an uninitialized block read as a flat failure — fixed (0.8.3)
- **Task:** read the unit-type table (`g_unit_type_table`, 2b5a:5232) and the order→badge-letter
  table (2b5a:54de) out of the data segment, to reproduce what the map draws.
- **Friction:** `read_bytes address="2b5a:5232" length=364` came back as
  `MemoryAccessException: Unable to read bytes at ram:2b5a:5232` — the identical message a bogus
  address produces, so the first reading was "I got the address wrong". The address was right and
  the failure *was* the answer: those bytes are in an uninitialized block because the tables are not
  compiled into the executable at all; the game parses them out of NAMES.TXT at startup. The single
  most important fact about that data, and the tool had it and threw it away.
- **Fix:** `read_bytes` now diagnoses the failure instead of forwarding it, distinguishing three
  cases — mapped nowhere (address wrong, or never loaded), inside an uninitialized block (named,
  with its bounds), or a genuine read error in an initialized block. The uninitialized message says
  the bytes were never in the image, that this is usually the answer rather than a problem, and
  points at `xrefs direction=to … [WRITE]` to find what builds them at run time. `inspect` also
  annotates its existing `Block:` line with `[UNINITIALIZED — …]`, which was the entry's "better
  still" ask: the block name alone made a BSS address look identical to a data one.
  Diagnosis happens in the `catch`, not as a pre-check, so the success path is untouched and the
  explanation can never disagree with what the read actually did.
- **Bonus, which is really the more useful fix:** a short read is now footed with
  `(read 9 of 64 requested — the range runs off the end of readable memory at …)`. `Memory.getBytes`
  returns a partial count rather than throwing when a range *starts* readable and runs out, so a
  truncated dump used to be presented as the whole answer with nothing marking it.
- **Process gap this exposed:** `read_bytes` had **no smoke coverage at all** — a registered program
  tool that the script never called, despite CLAUDE.md requiring one call per tool. It now has four,
  covering every branch above, and they are cheap because the compiled ELF target has a `.bss`.
- **Verified live (0.8.3)** against the entry's exact calls: both 2b5a:5232 and 2b5a:54de now report
  `inside 'DATA' (2b5a:2cc5-2b5a:e954), an UNINITIALIZED block`, and following the hint the message
  gives lands on `text_load_game_tables+1305 [WRITE]` — the loader that fills the table, i.e. the
  conclusion the original entry reached by inference. `inspect` shows the `[UNINITIALIZED]` marker on
  `g_unit_type_table`, and an ordinary read (`1d1d:07e4`) is unchanged. Headless: the ELF header
  reads normally, `.bss` gives the diagnosis, `0x7fffff000000` gives "nothing is mapped", and a read
  past the last block gives the short-read footer.

## 2026-07-14 — `manage_types` — could only rename a field, not split or retype one — fixed (0.9.0)
- **Task:** the colony record's `unkd[8]` turned out to be two per-nation arrays
  (`seen_population[4]` at `+0xba`, `seen_defense[4]` at `+0xbe`), and `savegame_colony` should say
  so, matching the project's canonical `src/savegame.h`.
- **Friction:** `rename_field` renames in place, so there was no way to replace one 8-byte array
  with two 4-byte ones. `define_types` would mean re-declaring the whole 202-byte struct to change
  8 bytes of it, and re-applying it everywhere. The workaround left the Ghidra type *less* precise
  than the C header it was imported from.
- **Fix:** `op=set_field` — retype (and optionally rename) whatever occupies a byte offset.
  Placement is by offset rather than field name precisely because the interesting offset is often
  *not* a field start: a split means writing at the old field's start and again at its midpoint.
  No `count` argument as the entry suggested; `type` carries array syntax (`byte[4]`) through
  `DataTypeParser`, which is what `set_data_type` and `set_function_signature` already do.
- **The part the entry didn't know it needed: `freeze_layout`.** Probing the real
  `savegame_colony` (with a deliberately out-of-range offset, so nothing was written) showed it has
  **packing enabled** — which is how `define_types` creates anything parsed from C, so it is the
  shape a real record actually has. On a packed struct Ghidra recomputes every offset on repack and
  treats an offset that isn't inside a component as an *insert* that shifts everything after it, so
  honouring a caller's offset is impossible. Refusing outright would have made the feature useless
  for exactly the case it was built for. Instead it refuses by default and names `freeze_layout=true`,
  which turns packing off first: verified in `StructureDataType.repack`, which calls
  `adjustNonPackedComponents()` rather than recomputing when packing is off, so the offsets are kept
  exactly as they stand and only stop being recalculated. The result says so loudly, because it
  changes the whole type rather than one field.
- **Self-guiding output.** A shrink leaves undefined bytes where the rest of the old field was, and
  the result names them (`That leaves 4 undefined bytes at +0x8..+0xb`) plus echoes the surrounding
  fields. Without that, a half-finished split reads as a finished one — and there is still no tool
  that dumps a type's layout on its own, so the echo is the only feedback available.
- **Verified headless** (`smokeTest`, which had no `set_field` coverage to regress): the non-packed
  path widens a field then splits it in two; the packed path refuses, then with `freeze_layout=true`
  splits `unsigned char pad[8]` into `lo`/`hi` at +0x4/+0x8 with `head` still at +0x0 and the struct
  still 12 bytes, confirming the freeze preserved the layout. Refusals covered: offset past the end,
  an unparseable type, and a non-struct.
- **Verified live afterwards — and the live run paid for itself (0.9.1).** Repeating the exercise
  against VICEROY on a throwaway type caught a bug the headless test could not, purely because the
  target is 16-bit: `unsigned int` is 2 bytes there, so `pad[8]` sat at `+0x2` rather than `+0x4`
  and the test offset landed in the *middle* of it. `replaceAtOffset` handled that fine, but the
  result only reported the undefined bytes *after* the new field, silently orphaning the ones in
  front — the very "half-finished split reads as finished" failure the gap report exists to
  prevent, implemented for one side only. Both sides are now reported, plus a note when the offset
  was inside the previous field rather than at its start, since landing mid-field usually means the
  caller's model of the layout is wrong and the edit will have "worked" anyway. Covered headless by
  a dedicated mid-field case so it cannot come back.
- **Verified live on 0.9.1**, repeating the call that exposed the bug: it now reports
  `2 bytes at +0x2..+0x3 and 2 bytes at +0x8..+0x9 … still undefined` plus the mid-field note, where
  0.9.0 named only `+0x8..+0x9`. Following that guidance to its conclusion — filling both gaps —
  leaves the record fully described with no undefined bytes anywhere
  (`head`/`before`/`lo`/`after`/`tail`, 12 bytes), which is the point: the output has to be
  actionable, not merely correct. The throwaway type was deleted afterwards and
  `savegame_colony` was only ever probed with an out-of-range offset, so it remains packed and
  unmodified.
- **Not done:** the real `savegame_colony` split has NOT been applied; that is a change to the RE
  project's data, not to this server. `set_field` + `freeze_layout=true` at `+0xba` and `+0xbe` is
  now all it takes — and note the 16-bit `int` caveat above when picking those offsets.

## 2026-08-02 — `import` — no way to import a headerless binary: can't pick loader, language or base address
- **Task:** Import two iPXE PXE network bootstrap images (`undionly.kpxe`,
  `x86_64-pcbios-undionly.kpxe`, from https://boot.ipxe.org) into the `ipxe` project. These are
  headerless real-mode images: byte 0 is `ea 08 00 c0 07` (`JMPF 07c0:0008`), and the PXE stack loads
  them at linear `0x7C00`.
- **Friction:** `import {file: "/home/erikberg/src/ipxe-config/undionly.kpxe"}` failed with

  > `import failed: ghidra.app.util.opinion.LoadException: No load spec found`

  This is not a bug — it is the documented behaviour ("Ghidra auto-detects the format") meeting a file
  no loader claims. `BinaryLoader` returns a load spec flagged as requiring a language/compiler spec,
  and `AutoImporter`'s best-guess path skips exactly those, so a raw binary can *never* import through
  this tool no matter what the file is. The tool takes only `file` and `folder`; there is nowhere to
  say "Raw Binary, x86:LE:16:Real Mode, base 07c0:0000". Nothing else in the server fills the gap
  either: `create` works inside an existing program, `migrate` copies documentation between two
  programs that already exist, and there is no image-base or set-language tool, so even a
  hypothetically-imported blob couldn't be rebased afterwards.
- **Expected:** optional passthrough on `import` for the three things the GUI's import dialog asks for
  when auto-detect comes up empty — `loader` (e.g. `"Raw Binary"` / `BinaryLoader`), `processor`
  (a language ID like `x86:LE:16:Real Mode`, plus `cspec`), and loader options, of which
  `base_address` is the one that matters for raw images. Headless already models all of this as
  `-loader` / `-processor` / `-cspec` / `-loader-baseAddr`, so it's a matter of forwarding, not new
  machinery. A hint in the `LoadException` text — "no loader claims this file; pass `loader` +
  `processor` to load it raw" — would also have shortened the dead end considerably.
- **Workaround:** left the server entirely. Closed the project
  (`manage_project op=close` — this part worked well, and made the workaround possible at all), ran
  the external CLI against the now-unlocked project directory:

  ```
  .../dailydriver/Ghidra/RuntimeScripts/Linux/support/analyzeHeadless \
    /home/erikberg/src/ipxe-config ipxe \
    -import .../undionly.kpxe -import .../x86_64-pcbios-undionly.kpxe \
    -loader BinaryLoader -loader-baseAddr 07c0:0000 \
    -processor "x86:LE:16:Real Mode" -cspec default -noanalysis
  ```

  then `manage_project op=open` to get back in. Both programs loaded correctly and
  `create kind=instructions` at `07c0:0000` disassembles the iPXE prefix as expected, so the resulting
  state is exactly what an options-carrying `import` would have produced in one call.
- **Cost of the workaround:** it needs a *matching* Ghidra install on disk (found by guessing from the
  `read_log` path that the running instance is the `dailydriver` build) and it needs the project
  closed, which is a heavier, more disruptive operation than the task deserved — for a project with
  other work open, `on_dirty` handling and reopening make it genuinely risky rather than merely
  annoying. Roughly half a dozen extra calls, a `Bash` hunt for the right install, and a full
  headless JVM startup to do a one-call job.
- **Resolved (0.10.0):** `import` takes optional `loader` (class simple name like `BinaryLoader` or
  display name like `Raw Binary` — resolved via `ClassSearcher` so a miss lists every valid loader),
  `processor`, `cspec` and `base_address`, forwarded straight to `ProgramLoader.Builder`
  (`.loaders(Class)` / `.language` / `.compiler` / `addLoaderArg("-loader-baseAddr", …)`) — the same
  chain headless uses. `cspec` or `base_address` without `processor` is refused up front (an address
  literally cannot parse without a language; Ghidra's own failure for that case is the opaque
  "Cannot load with null options"), and the bare no-loader failure now carries the requested hint
  naming `loader`/`processor`/`base_address`. Smoke imports the build's own `target.c` (claimed by
  no loader) raw at `07c0:0000` via the display name and asserts the bytes landed there plus the
  hint on the bare call. (Note: `BinaryLoader` places the memory *block* at the base address; the
  program's image-base property stays `0000:0000` — assert `getMinAddress()`, not `getImageBase()`.)
- **Verified live on 0.10.0** (git 057d8ac), repeating the exact scenario against the running
  `ipxe` project: `import {file: …/undionly.kpxe, folder: "/scratch", loader: "Raw Binary",
  processor: "x86:LE:16:Real Mode", base_address: "07c0:0000"}` loaded in one call — no project
  close, no external CLI — and `create kind=instructions` + `disassemble` at `07c0:0000` gave
  `JMPF LAB_07c0_0008`, byte-identical to what the headless workaround produced. The scratch copy
  was deleted afterwards; the two programs imported via the original workaround were untouched.

## 2026-08-31 — `fid_apply` — said how many functions it named, never which — fixed (0.11.0)
- **Task:** (reported by the MSC 6.0 CRT-naming session on the `mads` project) propagate names from a
  hand-labelled CRT object across ~600 sibling OMF objects with `fid_apply`.
- **Friction:** the result was `Applied N FID name(s)` and nothing else. Learning *what* changed
  meant diffing `list kind=functions user_only=true` before and after every call; multi-match
  conflicts were invisible unless you went looking for `FID_conflict:` labels.
- **Expected:** one line per function — address, previous name, new name, match score, source
  library — plus the candidates it declined to apply and why.
- **Resolved (0.11.0):** Ghidra's `ApplyFidEntriesCommand` keeps all of that private, so the tool
  runs the same `FidService.processProgram` search once more *before* the command (one extra hash
  pass — cheap next to the DB queries) to learn the candidates, and diffs the symbol table around
  the command's `getFIDLocations()` to learn what was applied. Output: `Applied:` lines
  (`addr  old -> new  [conflict: also …]  score S  from name (lib ver variant)`), then
  `Matched but not renamed (N):` with the reason — `kept (user/imported name; FID never overrides
  one)` is the command's own gate, otherwise `not applied` with the candidate list, and a footer
  stating the multi-name threshold rule. Gotcha found by the smoke: a `FunctionRecord`'s name is a
  lazy strings-table lookup, so every candidate must be rendered *while the query service is
  open* — reading it after the try-with-resources closes NPEs in `FidDB.getStringsTable()`.
  Smoke: `fid_build` from the named build, `fid_apply` on a stripped twin, asserting the report
  names `mix` (a name only the database could have supplied).

## 2026-08-31 — `import` — one host file per call; an OMF `.LIB` rejected outright — fixed (0.11.0)
- **Task:** import a split MSC `.LIB` — 670 OMF objects — into a project (same session as above).
- **Friction:** `import` took one `file`, so that was ~1400 sequential tool calls across three agents
  (import + analyze each). The `.LIB` itself (magic `0xF0`) came back "No load spec found" even
  though Ghidra ships `OmfArchiveFileSystem`.
- **Expected:** a directory or glob with one summary result, an `analyze=true` flag, and a `.LIB`
  importing straight into a folder as one program per member.
- **Resolved (0.11.0):** `file` is a file, a directory (its files, one level) or a glob (`*`, `?`,
  `[..]`, `{a,b}`, `**` recursing), expanded with a `PathMatcher` under the longest glob-free prefix.
  A file no loader claims is probed with `FileSystemService.probeFileForFilesystem`; if it is a
  container (OMF `.LIB`, `ar`/COFF archive, zip…) every member file is imported via
  `ProgramLoader.Builder.source(FSRL)` — the same route the GUI's batch import takes. `analyze=true`
  queues every created program on the new shared `util/Analysis` worker (one analysis at a time;
  `analyze` uses the same queue now, so a bulk import no longer spawns a thread per program). The
  summary lists created paths (capped at 200, then points at `list_files`), per-file failures, and
  how many analyses were queued. Single-file calls keep their old error shape (the raw-binary hint,
  the `cspec`/`base_address` dependency refusals). Smoke: a `*.bin` glob importing two ELFs with
  `analyze=true` (waited on via `Analysis.awaitIdle`), an empty glob, and an `ar` archive of the
  object expanding to `/bulk/archive/target.o` — Ghidra's `CoffArchiveFileSystem` claims GNU `ar`
  too. Not verified here: an actual OMF `.LIB` (none on this machine); the code path is the same
  probe, so the `mads` session is the place to confirm it. (Status: **verified live on 0.12.1**
  from this session after the mads run deferred it — one `import` of
  `~/dosbox/RTLTEST/LIB/LLIBC7.LIB` produced 596 member programs via `OmfArchiveFileSystem`,
  `qsort` spot-checked as a real Program, scratch folder deleted after.)

## 2026-08-31 — `create` — no way to turn every named label into a function at once — fixed (0.11.0)
- **Task:** (same session) make `fid_build` see the OMF objects' entry points. OMF imports leave
  most PUBDEF entry points as plain labels, and `fid_build` ingests only *functions* with
  non-default names.
- **Friction:** the pass was label-by-label `batch create kind=function` over ~600 programs (~444
  creations for the 74 RTLUTILS objects alone).
- **Expected:** one program op that creates a function at every user/imported-named label in
  executable memory, skipping labels that sit on defined data.
- **Resolved (0.11.0):** `create kind=functions_at_labels` (no `address` — `required` is now just
  `kind`, and the other kinds say "address is required for kind=…"). Trusted means the FID
  analyzer's own bar, `SourceType.IMPORTED` or higher, so analysis-made `LAB_`/switch labels are left
  alone. A label inside another function's *body* still gets a function (the earlier function's
  flow ran through it — the adjacent-CRT-routine case); only a function already *starting* there
  disqualifies it. Reports created / already-function / on-data / not-executable counts and names
  the created ones (capped at 50). Smoke: `clear kind=function helper` leaves the imported label,
  the sweep recreates exactly `helper` (41 labels seen, 3 already functions, 37 data-side).

## 2026-08-31 — `fid_build` — no way to see why a build came out thin — fixed (0.11.0)
- **Task:** (same session) diagnose a poor `.fidb` — ingested far fewer functions than expected.
- **Friction:** the result was `Ingested N of M functions`; the skip reasons (husks failing the
  minimum short-hash length, default names, thunks) could only be guessed.
- **Expected:** per-program counts of ingested vs. skipped with the reasons.
- **Resolved (0.11.0):** the summary now breaks the skips down from Ghidra's own
  `FidPopulateResult.getFailures()` — unnamed (default name), thunks, too short to hash (< 4 code
  units, the husk case), duplicates, unreadable bytes — and a zero-ingest build says to name
  functions first (pointing at `create kind=functions_at_labels`). `detail=true` adds one line per
  program: Ghidra only totals dispositions, so the per-program pass re-applies its rules
  (default-name, thunk, `FidHasher.hash == null`) with the same hasher; it cannot see the duplicate
  check, which is global across the build.

## 2026-08-31 — `fid_build` — ingested analyzer-made names, so `fid_apply` stamped guesses as facts — fixed (0.12.0)
- **Task:** (MSC 6.0 CRT-naming run, `mads`) build a `.fidb` from NEBULAR and apply it to SPHERE.
- **Friction:** the build picked up the RTLink extension's overlay-function auto-names
  (`OVLnn_xxxx`), and `fid_apply` then stamped `OVL61_0010` onto SPHERE's resident CRT routine at
  `160f:2cfa` — a real library function (probably `qsort`). Ghidra's
  `FidServiceLibraryIngest` skips only `SourceType.DEFAULT` names; every other source is ingested.
- **Expected:** skip ANALYSIS-sourced names too, or a name-pattern exclusion, as a `fid_build` option
  with a sensible default. Ownership was settled between sessions: the policy lives here
  (`ghidra-dailydriver` confirmed core deliberately ingests all named functions), and
  `ghidra-plugin-rtlink` guarantees its auto-names are `SourceType.ANALYSIS` so the default is
  principled.
- **Resolved (0.12.0):** `fid_build` passes a `functionFilter` to `createNewLibraryFromPrograms`:
  a function is ingested only if its name is USER_DEFINED or IMPORTED — the same bar the FID
  analyzer applies before overwriting — unless `include_analysis_names=true`; `exclude` is a regex
  (find semantics, validated up front) dropping matching names either way. Filtered functions
  show up as "N analyzer-named or excluded" in the breakdown (and as the `filtered` column of
  `detail=true`), and a zero-ingest build now points at `include_analysis_names`. Smoke: a build
  from the stripped twin after `fid_apply` filters exactly the 5 stamped names and keeps the ELF
  loader's 4 imported ones; `include_analysis_names=true` filters 0; `exclude='^mix$'` drops
  exactly one; an unclosed regex is refused.

## 2026-08-31 — `create kind=function` — a silent 1-byte husk on bytes nothing had decoded — fixed (0.12.0)
- **Task:** (same run) create functions at entry points that auto-analysis never reached.
- **Friction:** on never-disassembled bytes, `create kind=function` returned a 1-byte function
  without complaint. Agents learned to `create kind=instructions` first and re-create.
  `end_address` was also documented as *forcing* the body, but Ghidra renormalises to flow.
- **Cause:** `CreateFunctionCmd` never disassembles. With no instruction at the entry,
  `getFunctionBody` follows flow from the one *undefined* code unit and gets exactly that byte —
  and `createFunction` only refuses when there is no code unit at all, which an undefined byte
  satisfies. The GUI's Create Function action disassembles first, which is why it never shows this.
- **Resolved (0.12.0):** `create kind=function` (and the `functions_at_labels` sweep) runs
  `DisassembleCommand` at the entry when no instruction is there — refusing outright if defined
  data sits there (say `clear kind=code` first) or the bytes do not decode — and the result says
  `disassembled N bytes first`. If a 1-byte body over an undefined byte still results, the result
  ends with `HUSK: …`, and the sweep counts those separately from created. The `end_address`
  description now says Ghidra renormalises the body to flow and that the result reports the size it
  kept. Smoke: clear `helper`'s code, create the function on the bare bytes, assert it disassembled
  first and came out 21 bytes, not 1.
- **Verified live on 0.12.1** (mads session): "disassembled N bytes first" appeared on ~15 real
  creations across the four game programs with zero husks, and six container splits landed at the
  planned sizes via the documented recipe (batch `clear kind=function` → re-create with
  `end_address`).

## 2026-08-31 — `rename kind=function` — refused when the wanted name was a secondary label at the entry — fixed (0.12.1)
- **Task:** (SPHERE/RETURN naming agents, `mads`) rename functions to their canonical CRT names
  after a games-wide FID propagation.
- **Friction:** "A symbol named X already exists at this address!" whenever the FID pass had left X
  as a *secondary* label at the same entry — ~40 cases per program. `rename kind=label` could not
  reach it because it retargets the primary symbol, i.e. the function.
- **Workaround:** `clear kind=label name=X` at the address, then rename — two calls per function.
- **Resolved (0.12.1):** the intent is unambiguous (make X *the* function), so `rename
  kind=function` deletes a non-primary label of that exact name at the entry before `setName`, and
  the result says `(absorbed the secondary <source> label 'X' …)`. Smoke: a `create kind=label`
  beside `helper`, then a rename to that name, asserting the absorb note.

## 2026-08-31 — `create kind=function end_address` — cannot shrink an existing function — documented (0.12.1)
- **Task:** (same run) re-bound five SPHERE functions whose containers had swallowed never-decoded
  bytes.
- **Friction:** with `end_address` over an existing function the result said "body N bytes
  (requested M; Ghidra normalized it to the flow-derived body)" and nothing shrank; the five came
  back as husks.
- **Resolved (0.12.1, documentation):** the tool text now states that Ghidra renormalises the body
  to flow and so `end_address` cannot shrink an existing function whose old body holds undecoded
  bytes — `clear kind=function` first, then create. The husk half is 0.12.0's disassemble-first
  fix (the entry gets decoded before the body is computed, and a leftover 1-byte body is named
  `HUSK`).

## 2026-08-31 — `create kind=function` on a JMP — a thunk plus a spurious target function, unannounced — fixed (0.12.1)
- **Task:** (same run) create the function at SPHERE `1967:1d4b`, which begins with a 3-byte JMP.
- **Friction:** Ghidra made `thunk_FUN_1967_1e40` and a `FUN_1967_1e40` at the jump target; both
  had to be deleted and the real entry created three bytes later. Expected Ghidra behaviour, but
  the result said only "Created function".
- **Resolved (0.12.1):** the result now ends with `THUNK to <name> @ <addr> (the entry is a JMP; if
  the real function starts after it, clear kind=function here and create there)`, and reports how
  many other functions Ghidra created as a side effect (`Ghidra also created N other function(s)`),
  computed from the function count around the command. Not smoke-tested: the ELF target has no
  JMP-first entry to create on — the branch is a report-only change.

## 2026-08-31 — `search_memory` — hits framed on the image base, not the containing block — fixed (0.12.1)
- **Task:** (RETURN agent) locate byte patterns in a segmented real-mode program and inspect them.
- **Friction:** every hit came back as `1000:(X+0x92c0)` for a block at `192c:X` — the linear
  address re-framed on the image base — while `read_bytes`/`inspect` take the block-relative
  `seg:off`, so each hit needed a hand conversion.
- **Cause:** `Memory.findBytes` returns the segmented address as it computes it, normalised on
  the search start (the image base); the listing and every other tool use the block's segment.
- **Resolved (0.12.1):** both search kinds re-frame a `SegmentedAddress` hit with
  `normalize(block.getStart().getSegment())` so it prints in the containing block's framing and
  pastes straight into the other tools. Flat address spaces are untouched (the smoke ELF exercises
  that path; the segmented one is verified by construction, not by smoke).
- **Verified live on 0.12.1** (mads session, RETURN): `9c fa 2e f6 06` returned
  `192c:0b3a  in $$VM_UNKR` etc. — block-relative framing with the containing-function
  annotation, pasteable straight into read_bytes/inspect.

## 2026-07-14 — `inspect` — assumed register context is invisible — fixed (0.13.0)
_Rewritten 2026-07-25. As first logged this entry asked for a read **and** a write path, on the
grounds that analyzer-baked context was "invisible and unfixable". The unfixable half was wrong, and
the write half now looks like the wrong layer — see "Why the write half was dropped" below. What
remains is the read path._

- **Task:** A program had `DS=DGROUP` asserted over the RTLink runtime's code blocks (segments
  `210d`/`275d`), where DS is emphatically not DGROUP — the overlay manager reloads DS from its own
  saved-segment slots and does `MOV DS,CS`. I needed to find out whether the bad context was still
  there.
- **Friction:** nothing in the server exposes `ProgramContext`, so there is no way to read a
  register's assumed value at an address. The question was answered only by `decompile` and
  eyeballing: seeing `_DAT_2b5a_0000` and `s_SAVEMEM_2b5a_2108` inside a function that plainly does
  `MOV DS,CS` is what told me the context was still asserted. That is an inference from a rendering,
  not a reading — and the inference only works when you already suspect the answer.
- **Expected:** `inspect` should report assumed register values at the address — DS/CS/SS at minimum
  for segmented programs, where it is the difference between a global resolving and not. That is the
  whole ask now: a reading, so a claim about context can be checked instead of inferred.
- **Why this matters beyond the one incident.** A lot of this project's fixes land in *analyzers*
  rather than in the server — `RTLinkXrefAnalyzer` for DS-relative xrefs, `RTLinkOverlayAnalyzer` for
  stub thunking and the stale-bookmark sweep, and the DS assumption here. Register context is the one
  piece of analyzer output with no MCP-side reading at all, so verifying it means opening the GUI or
  arguing backwards from a decompilation. Everything else an analyzer writes — symbols, references,
  bookmarks, thunk relationships, types — is directly inspectable.
- **Why the write half was dropped.** The original entry also wanted a `kind=register_context` write
  and a `context` kind on `migrate`. Both look wrong now: `RTLinkOverlayAnalyzer.assumeDataSegmentRegister`
  *owns* this assertion (it walks executable blocks doing `context.setValue(ds, …)` after sniffing
  DGROUP out of the C startup), and it re-applies on every pass. An MCP-side clear would simply be
  overwritten by the next analysis — so the durable place to express "DS is not DGROUP here" is the
  analyzer that knows why, which is where it ended up. Nothing in Ghidra core asserts DGROUP; this was
  never core behaviour.
- **Cause: fixed at source, in `ghidra-plugin-rtlink`.** The analyzer now skips the runtime blocks and
  logs it ("skipped N RTLink runtime block(s), where DS is not DGROUP"), and *clears* rather than
  merely skipping, so a program analyzed by the older build is retrofitted instead of staying wrong.
  This also retracts the original entry's claim that "an analyzer that only ever sets context can
  never unset it" — it unsets it now.
- **Resolved (0.13.0):** `inspect` now ends its header block with `Register context (assumed
  values):` — one line per register with an explicitly-set value at the address
  (`ProgramContext.getNonDefaultValue`, so analyzer/user assertions only, never language
  defaults), as `DS = 0x2b5a  [asserted over 210d:0000 - 210d:ffff]` — the range comes from
  `getRegisterValueRangeContaining`, so "is the bad context still there, and how far does it
  reach" is one call. Subregisters that merely inherit a parent's value are folded into the
  parent line, and the disassembly context register is skipped (internal state, not an
  assumption). There is still deliberately no MCP write path — the durable place to change an
  assumption remains the analyzer that owns it, exactly as this entry concluded. Smoke: sets GS
  at a function entry via the API and asserts the line + range appear.

## 2026-09-01 — `list` — no way to find a comment without already knowing its address — fixed (0.14.0)
- **Task:** (viceroy/main session, VICEROY.EXE in `mads`) update every plate/pre/eol comment
  containing a renamed term.
- **Friction:** `set_comment` writes at a known address and `inspect` reads at a known address,
  but nothing enumerates or searches comments — no path from "comments containing X" to the
  addresses that carry them. The workarounds were decompiling every candidate function (floods
  the context window) or grepping the on-disk `db.*.gbf` buffers (stale while the project is
  open, and text↔address adjacency is not reliable — the user rightly stopped that).
- **Expected:** `list kind=comments` with the standard filter/offset/limit (the requester's own
  first preference — it fits the tool shape exactly), or a search_comments action; optionally a
  replace mode.
- **Resolved (0.14.0):** `list kind=comments` — one line per (address, comment kind) pair as
  `address  [plate|pre|eol|post|repeatable]  text` (newlines escaped, text truncated at 300
  chars; `inspect` the address for the full text), walking only addresses that carry a comment
  (`Listing.getCommentAddressIterator`). The existing whole-line filter gives text, kind, AND
  overlay/segment scoping in one parameter (filter="OVERLAY_24:" works on this binary), and
  `min_address`/`max_address` — previously kind=functions only — now scope the walk too. The
  replace mode was deliberately NOT added: with the listing, a rename is `list kind=comments
  filter=X` + `batch` of `set_comment`, which stays inside the one-tool-per-intention rule.
  Smoke also closes a coverage gap found while adding this: `set_comment` had never been in the
  smoke script; it now writes a plate comment that the listing must find by text and that range
  scoping must exclude.
- **Verified live + verdict (0.14.0→0.16.0):** the requester ran the real rename (24 "dwelling"
  hits → "settlement") and reported the composition held — 1 list + 1 batch (24 ok), replace mode
  confirmed unnecessary ("the write side was never the problem — the read side was"). The one
  real cost: 20 of 24 comments exceeded the 300-char truncation, needing a noisy `inspect` each.
  Closed in 0.16.0 by `full=true` on kind=comments (skip truncation; gated to that kind).

## 2026-09-01 — `list`/`decompile` — undeclared-input functions discoverable only one decompile at a time; header wording overstated the hazard — fixed (0.15.0)
- **Task:** (viceroy/main session, VICEROY.EXE) find every hand-written register-argument helper —
  the functions whose decompilation reads `in_AX`/`in_EDI` inputs their prototype omits.
- **Friction:** the only discovery path was decompiling a function and reading the header warning;
  nothing enumerated the offenders. Ownership was triangulated across sessions first:
  ghidra-dailydriver confirmed it cannot be a core/cspec change ("inherently requires running the
  decompiler per function… server-side it's a check of each HighFunction's in_* symbols against
  the committed prototype").
- **Also wrong: the warning's mechanism.** The header said "the stack args around them may be
  mis-ordered". rtlink and dailydriver both corrected it: the decompiler never reorders declared
  parameters — each binds to storage computed from convention + declared types. A guessed
  prototype merely omits the register args (their true positions among the declared args are
  unknown); a WRONG committed prototype MIS-BINDS declared params to the wrong storage (verified
  on 061_strcpy.obj: declared `__src` bound to the high word of the far `__dest`). The requester
  had repeated our wording to their user as fact.
- **Resolved (0.15.0):** `list kind=undeclared_inputs` — decompiles every non-thunk, non-husk
  function in scope (8 concurrent over the shared pool; min_address/max_address scope it; cost is
  stated in the description) and lists offenders as `address  name  [guessed|committed]
  in_AX (AX:2), …`; a function that fails to decompile is listed as `<decompile failed>` rather
  than silently passed, and filter=guessed / filter=committed splits "needs a signature written"
  from "committed but provably incomplete". The decompile header and its docs now state the
  guessed/omitted vs committed/mis-bound mechanism instead of the reordering claim. Smoke: commit
  `int helper(void)` (parameterless but with a live return — a void return dead-code-eliminates
  the whole body and the in_EDI with it, which is itself worth knowing) → sweep flags
  `helper  [committed]  in_EDI (EDI:4)`; restore `int helper(int x)` → sweep is clean.
- **Ride-along verification:** the 2026-07-08 RETF near/far hint caught a real mistake in the
  wild — `__regcall` (near-only) proposed on a far hand-asm helper drew the "body contains a far
  return (RETF) but the calling convention is near" warning, and the caller reverted to
  `__cdecl16far` + custom storage. Logged by the requester unprompted.
