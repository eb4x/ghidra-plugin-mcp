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
[archive/mcp-feedback.md](archive/mcp-feedback.md) (27 entries): the `set_function_signature`
custom per-param storage (register / register-pair / stack) + custom `return` storage,
the `decompile` coverage header,
`xrefs`/`calls` honest-zero caveats, the OVERLAY_24 analyzer root-cause, `read_log`, `xRam…` global
resolution, the bare-address rename hint, `inspect` Variables + thunk-status, `decompile dump_symbols`,
`clear kind=local_variable|label|function`, `manage_types op=rename_field`, `create kind=function
end_address`, namespaced-symbol resolution, the `set_function_signature` RETF hint, the bounded
deferring save + `save` tool, the create-kind=thunk experiment (removed), `create kind=label
namespace` + `decompile dump_jumptables` (jump-table overrides), `manage_files` folder ops, and the
`manage_files` recursive-delete handle release._

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
  DS=DGROUP). Until then, the `search_memory` byte-pattern route is the answer, and
  `inspect`'s "Xrefs: 0 to" on a DS global should be read as "unknown", not "unused".

## Follow-ups on the 2026-07-09 entries (same day, after both were implemented)

- **`manage_files` folder delete: works.** `op=delete` on `/scratch-*` removed the empty
  folders, project back to its original 2 folders / 5 files. Nothing more needed.
- **`decompile dump_jumptables`: a client-side schema-cache artifact, not a plugin bug.**
  An MCP client that cached the tool's JSON schema at connect time stringifies a *new*
  parameter, and the server then rejects `"true"` with `/dump_jumptables: string found,
  boolean expected`. A client that re-reads the schema after the Ghidra restart calls it
  fine — the flag was exercised live against `/gog/VICEROY.EXE` the same day. Still worth
  knowing: adding a tool argument mid-session may not be testable in that session.
- **Pooled `DecompInterface` does *not* serve stale symbols — the flag does not lie.**
  The concern was that `Decompilers` reuses one `DecompInterface` per program and never
  calls `resetDecompiler()`, so the C++ side might cache symbol-scope queries and miss an
  override written after the program's first decompile. It does not:
  `DecompInterface.decompileFunction` calls `flushCache()` — which sends `flushNative` to
  the decompiler process — at the end of *every* decompile
  (`DecompInterface.java:832`), so the next decompile re-queries the symbol database.
  (`resetDecompiler()` restarts a dead process; it is not the cache-coherence mechanism.)
  Verified empirically on the same pooled interface, in one process: decompile
  `get_funky_string` → `decompiler-discovered (73 cases -> 13 distinct targets)`; write an
  override with `create kind=label namespace=…`; decompile again → `CONSUMED (16 cases ->
  3 distinct targets)`. The *decompiler's own* recovered table changed, so the C++ side
  plainly re-read the new symbols.
  **Re-confirmed 2026-07-09** by an independent rename probe on a fresh program — see the
  settlement at the bottom of this file. This bullet is correct; treat it as settled.

## Correction to the entry above: `dump_jumptables` reported a false NOT CONSUMED (2026-07-09)

Exercised the flag in a fresh session. It works, and it immediately paid for itself — but its
verdict line was wrong, and the bug is the same address-rendering trap that has now bitten this
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
- ~~The predicted stale-`DecompInterface` hazard is real.~~ **Settled empirically (2026-07-09): it
  is not.** This bullet contradicted the follow-up above it, so both were tested.
  - *Mechanism:* `DecompInterface.decompileFunction` ends by calling `flushCache()` whenever the
    process is `NOT_DISPOSED` (`DecompInterface.java:832`), which sends `flushNative` to the
    decompiler process. The native symbol cache is therefore empty *after every decompile*, so the
    next one must re-query the symbol database. (The `flushCache()` commented out with "we don't
    need to flush the cache" is at line 949, inside the unrelated `fillinVersionNumber`.)
  - *Experiment:* fresh `/bin/ls` imported and analysed, so no prior decompile could have warmed
    anything. Decompiled `ext_wmatch` (the program's **first** decompile) — it rendered its callee
    as `FUN_001054f4`. Renamed that callee, then decompiled `ext_wmatch` again on the same pooled
    interface: both call sites now render
    `STALE_PROBE_written_after_first_decompile()`. A symbol written *after* the first decompile is
    visible to the next one.
  - *So there is no "write the override before the first decompile" rule*, and `resetDecompiler()`
    is not needed for cache coherence — it restarts a dead process, as the follow-up above says.
  - *What most likely burned the earlier measurement:* the false `NOT CONSUMED` verdict this very
    entry documents. Before `44f6082` the dump compared switch addresses as **strings**, so an
    override that had in fact been consumed was reported as not consumed. "Decompile, add override,
    decompile again → still not consumed" is exactly what that bug looks like from the outside, and
    it is the reading that mimics staleness. (Inference, not proven — but it fits the symptom, and
    staleness is now ruled out.)
- Minor: `manage_files op=delete recursive=true` refusing with "open elsewhere" when the plugin's
  own cached handle held the program — **resolved and archived**; the pre-flight now runs after
  `releaseDescendants`.
