# ebbex-ghidra-mcp — Dogfooding Feedback

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
[archive/mcp-feedback.md](archive/mcp-feedback.md) (37 entries): the `set_function_signature`
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
addresses (`g_savegame_head` 5370) legitimately stays at 0._


## 2026-07-13 — bookmarks — no way to read error bookmarks (Bad Instruction etc.)
- **Task:** Diagnosing why OVERLAY_19::011958 was never disassembled on a fresh
  import (the 1-byte-husk investigation). The disassembler records its failures as
  ERROR bookmarks ("Bad Instruction", "Failed to disassemble at X due to
  conflicting ..."), which would have distinguished "never attempted" from
  "attempted and conflicted" in one call.
- **Friction:** No tool exposes bookmarks: `inspect` shows comments but not
  bookmarks, and `list` has no `kind=bookmarks`.
- **Expected:** `list kind=bookmarks` (type/category/comment/address, filterable),
  and/or bookmarks included in `inspect` output.
- **Workaround:** Added temporary Msg.debug probes to Disassembler/DisassemblerQueue
  through Eclipse and re-ran the import per hypothesis — five Ghidra restarts where
  one bookmark listing might have sufficed.

## 2026-07-13 — disassemble — undefined bytes at the requested address are skipped silently
- **Task:** Same investigation: `disassemble address=OVERLAY_19::011958 count=...`
  to see the (expected) code there.
- **Friction:** The address held undefined bytes, and the output silently started at
  the next instruction (011d8c) with nothing indicating the requested address was
  skipped. Read as "function has no code; next instruction at 011d8c" it cost both
  the human and the agent a wrong first theory — it looks like the tool disassembled
  the gap and found nothing, when it never looked at those bytes at all.
- **Expected:** A leading marker line when the requested start is not on a code unit,
  e.g. "011958: undefined bytes (0x434 undefined until 011d8c)" — same for offcut
  starts.
- **Workaround:** `read_bytes` + `inspect` to establish the bytes were undefined,
  then `create kind=instructions` to prove they decode.

## 2026-07-13 — list kind=functions — no body size, so husk functions can't be enumerated
- **Task:** Measure the blast radius of the 1-byte-husk bug: count functions whose
  body is implausibly small (1 byte / no instruction at entry) on a fresh import.
- **Friction:** `list kind=functions` shows entry, caller count and signature but
  not body size or an instruction-at-entry flag; the only per-function source of
  body size is `inspect`, which would have meant ~2800 calls.
- **Expected:** Body size (bytes) per line, or a filter like `min_body`/`max_body`
  (or a `husks` filter: body==1 or no instruction at entry).
- **Workaround:** Built the enumeration into the fork's RTLinkOverlayAnalyzer
  repair pass and read the count from `read_log` (343 of 2810 functions pre-fix).

## 2026-07-13 — list kind=bookmarks filter=error — RESOLVED: the ERROR channel was 100% false positives
- **Task:** Trust `list kind=bookmarks filter=error` as the "what could the disassembler
  not decode" channel. A fresh VICEROY.EXE import reported 541-ish ERROR bookmarks;
  every one was a fossil, so the channel said "541 things are broken" on a DB where
  nothing was.
- **Finding:** All of them sat in the two RTLink stub segments (281f/CODE_99,
  2a1f/CODE_100), on dispatch stubs that `RTLinkOverlayAnalyzer` had in fact resolved.
  A stub's `JMPF 0000:offset` only becomes valid when the overlay manager patches it at
  run time, so any disassembly of it records "Could not follow disassembly flow into
  non-existing memory". The analyzer then relocates and thunks the stub, but never
  removed the mark it had invalidated.
- **Correction to the original diagnosis:** the mark is not left over from an *earlier*
  pass. `RTLinkOverlayAnalyzer` runs at `FORMAT_ANALYSIS.after()` (it has to — it creates
  the overlay blocks everything else depends on), so on a fresh import it resolves each
  stub *before* the disassembler ever walks into it: the marks are stamped **after** the
  analyzer is done, and are stale the moment they are written. Clearing at resolve time
  alone fixes only the retrofit/one-shot path (540 → 2 on a re-run) and does nothing on
  a fresh import.
- **Fix (fork `rtlink`, RTLinkOverlayAnalyzer):** `createThunkAtStub()` now reports
  whether the stub is really resolved; resolved stub bodies are cleared *and recorded*,
  and swept again in `analysisEnded()`, once every other analyzer has run. Stubs whose
  resolution genuinely failed keep their mark and their log line.
- **Measured:** fresh import + full analysis, ERROR bookmarks **540 → 2** (analyzer logs
  "Cleared 538 stale Bad Instruction bookmark(s)"). Both survivors are real:
  `281f:0f71` (a CALLF+JMPF pair whose CALLF does not target a discovered dispatcher, so
  it is not a dispatch stub and stays unresolved) and `275d:0778` ("Maximum run of
  repeated byte instructions exceeded" — a run of 00 bytes walked as code). No
  regressions: 2793 functions, 611 stubs + 370 trampolines resolved, 29 xrefs to
  `2b5a:540e`, 3 one-byte functions (all real, no husks).
- **Takeaway:** `filter=error` now means something on VICEROY — worth re-checking after
  any analyzer change, since a diagnostic channel that is all noise is worse than none.
