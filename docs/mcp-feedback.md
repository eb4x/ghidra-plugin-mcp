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
