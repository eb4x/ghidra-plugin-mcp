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
[archive/mcp-feedback.md](archive/mcp-feedback.md) (39 entries): the `set_function_signature`
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
its own stale marks (540 → 2, both survivors real)._


## 2026-07-14 — migrate — `signatures` silently drops custom storage, producing *wrong* decompilation
- **Task:** Decide whether a re-import + `migrate` could recover a program whose
  **analyzer-baked state** was wrong (a stale `DS=DGROUP` register context over the
  RTLink runtime's code blocks). Migration is the documented answer to "re-import
  without losing the work", so the question was what it actually preserves.
- **Friction:** It preserves a great deal — measured on VICEROY.EXE, `dry_run` reported
  142 function names, 95 signatures, 125 comments, 39 data types, 6 labels, 28 defined
  data. But `signatures` round-trips through the **C prototype only**, so any signature
  pinned with `set_function_signature`'s `parameters[].storage` / `return.storage` comes
  back re-derived from Ghidra's default calling convention. Those functions do not fail
  loudly — they decompile **wrong**:
  - `fseek` (`1d1d:0a3e`), pinned `offset@Stack[0x6]` because MSC pushes a `long`
    unaligned and Ghidra's 16-bit cspec 4-byte-aligns it, came back at `Stack[0x8]`.
    `origin` slid with it, and the body reverted to reading `origin` out of `offset`'s
    high word: `if (0x2ffff < offset)` instead of `if (2 < origin)`.
  - `crt_fstrcpy` (`1d1d:117e`), a far-pointer routine returning in `DX:AX`, lost the
    return storage — so Ghidra decided the 4-byte return needed a hidden pointer and
    invented `__return_storage_ptr__` at `Stack[0x4]`, shifting `dest`/`src` to
    `Stack[0x8]`/`Stack[0xc]`. Every argument is now at the wrong offset.
  18 of the 95 signatures on this program are custom-storage (6 with `long` params/returns,
  12 far-pointer string routines). All 18 regress, and nothing in the migrate report says so.
- **Expected:** `signatures` should carry `VariableStorage` (custom param + return storage,
  and the "has custom storage" flag), not just the prototype. Failing that, the report
  must **name the functions whose custom storage could not be carried** — the same way it
  already calls out HUSK/body-mismatch entries, which is exactly the right instinct. A
  silent downgrade from "pinned, correct" to "inferred, wrong" is the worst outcome,
  because the decompilation still looks plausible.
- **Workaround:** Avoided migration entirely; fixed the analyzer so the state could be
  repaired in place instead (see the next entry). Had I migrated, I would have shipped 18
  quietly-wrong functions.

## 2026-07-14 — no register-context tool — analyzer-baked context is invisible and unfixable
- **Task:** A program had `DS=DGROUP` asserted over the RTLink runtime's code blocks
  (segments `210d`/`275d`), where DS is emphatically not DGROUP — the overlay manager
  reloads DS from its own saved-segment slots and does `MOV DS,CS`. I needed to (a) find
  out whether the stale context was still there and (b) take it back out.
- **Friction:** Nothing in the server exposes `ProgramContext`. There is no way to read a
  register's assumed value at an address, and no way to set or clear one over a range. So:
  - **(a)** was answered only by `decompile` and eyeballing: seeing `_DAT_2b5a_0000` and
    `s_SAVEMEM_2b5a_2108` inside a function that plainly does `MOV DS,CS` is what told me
    the context was still asserted. That is an inference from a rendering, not a reading.
  - **(b)** had no answer at all. `migrate`'s `kinds` has no `context`, and re-analysis
    cannot help either: an analyzer that only ever *sets* context can never unset it.
- **Expected:** `inspect` should report assumed register values at the address (DS/CS/SS at
  minimum, for segmented programs — it is the difference between a global resolving and not).
  And a way to write them: e.g. `set_data_type`-style `kind=register_context` with
  `register`, `value` (or absent = clear), `address`/`end_address`. Also a `context` kind on
  `migrate`, since it is program documentation in every sense that matters.
- **Workaround:** Changed the fork's `RTLinkOverlayAnalyzer` to be *corrective* — it now
  re-runs on every pass and explicitly `ProgramContext.remove()`s DS over the runtime blocks —
  and drove it with `analyze analyzer="RTLink/Plus Overlay"`. That works, and the one-shot
  `analyzer` parameter is genuinely the right escape hatch, but it means the only way to edit
  program state of this class is to go and write Java.

## 2026-07-14 — xrefs / clear — no way to ask "which references come *from* this range?"
- **Task:** Delete every reference **from** the RTLink runtime (`210d`, `275d`) **into**
  DGROUP — the ones an over-broad `DS` assumption had invented. A bounded, well-defined set:
  one from-range, one to-range.
- **Friction:** Two gaps compounded.
  1. `xrefs direction=from` takes a *location*, and on a function it returns only the refs
     from the **entry address**, not from the body: `xrefs location=FUN_210d_4454 direction=from`
     → "No from references", while `210d:449b` (inside it, +71) plainly had one. There is no
     from-range query at all, so "refs out of segment 210d" is not askable.
  2. So I had to invert it: enumerate every DGROUP symbol the runtime could possibly name
     (1043 of them, bounded by the runtime segments' own extents), call `xrefs direction=to`
     on each, and filter the from-side by segment. ~1043 calls to find 437 references.
     Then `clear kind=reference` takes exactly one `(address, to_address)` pair, and `batch`'s
     `op` enum has no `clear` — so that was 437 more calls.
- **Expected:** `xrefs` with a from-range (`min_address`/`max_address`, or accepting a function
  and meaning its whole body) and an optional filter on the other endpoint; and either a
  ranged `clear kind=reference` or `clear` as a `batch` op. Any one of the three would have
  turned ~1500 calls into a handful.
- **Bonus hazard, worth a guard:** my *first* attempt at this audit diffed `DAT_` labels
  between a good and a bad DB — and silently missed most of the bogus references, because I
  had already applied `savegame_unit[300]` over the region and the array **absorbed the
  interior `DAT_` labels**. The references still existed; their labels did not. A label-based
  audit is not a reference-based audit, and `list kind=symbols` gives no hint that a typed
  region is swallowing referenced addresses. A real from-range `xrefs` query would have made
  the mistake impossible.
