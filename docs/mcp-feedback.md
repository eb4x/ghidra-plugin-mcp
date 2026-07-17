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
[archive/mcp-feedback.md](archive/mcp-feedback.md) (42 entries): the `set_function_signature`
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
thunks)._


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

## 2026-07-14 — `manage_types` — `op=rename_field` cannot split/retype a field, only rename it
- **Task:** The colony record's `unkd[8]` turned out to be two distinct per-nation arrays
  (`seen_population[4]` at `+0xba`, `seen_defense[4]` at `+0xbe`). I wanted the Ghidra
  `savegame_colony` type to say so, matching the project's canonical `src/savegame.h`.
- **Friction:** `rename_field` renames in place; there is no way to replace one 8-byte array
  field with two 4-byte ones. `define_types` would mean re-declaring the whole 202-byte
  struct just to change 8 bytes of it, and re-applying it everywhere.
- **Expected:** a field-level edit on an existing struct — e.g. `op=set_field` with
  `offset`, `type`, `name` (and a `count` for arrays) — so a struct can be refined
  incrementally as the RE lands, which is how struct knowledge actually arrives.
- **Workaround:** Renamed the array to `seen_population_and_defense` (`op=rename_field`,
  field `0xba`) and let `src/savegame.h` carry the real split. The Ghidra type is now
  *less* precise than the C header it was imported from.

## 2026-07-14 — `read_bytes` — an uninitialized block reads as a flat failure, hiding the real news
- **Task:** Read the unit-type table (`g_unit_type_table`, 2b5a:5232) and the order->badge-letter
  table (2b5a:54de) out of the data segment, to reproduce what the map draws.
- **Friction:** `read_bytes address="2b5a:5232" length=364` →
  `read_bytes failed: ghidra.program.model.mem.MemoryAccessException: Unable to read bytes at
  ram:2b5a:5232`. The same message would come back for a bogus address, so my first reading was
  "I got the address wrong". In fact the address was right and the failure WAS the answer: those
  bytes live in an uninitialized (BSS) block, because the tables are not compiled into the
  executable at all — the game parses them out of NAMES.TXT at startup. That is the single most
  important fact about them, and the tool had it and threw it away.
- **Expected:** distinguish the two cases. If the address resolves to a memory block that is not
  initialized, say so — `2b5a:5232 is in uninitialized block DATA (no bytes in the image)` —
  rather than a generic access failure. Better still, `inspect` should report the containing
  block's initialized flag; it already prints the block name, so the caller has no way to tell an
  initialized block from a BSS one today.
- **Workaround:** Noticed that BOTH tables failed the same way, went looking for their writers with
  `xrefs direction=to ... [WRITE]`, found `data_load_names_text` on both, and went to the data file.
  The right conclusion, reached by inference rather than by being told.

## 2026-07-16 — VICEROY.EXE UI geometry RE (overlay stub resolution)

- **What I tried:** `decompile` / `calls` on RTLink overlay thunks, e.g. `OVLSTUB_20_0EB0`,
  `OVLSTUB_08_0424`, `OVLSTUB_09_093C`.
- **What I expected:** to be pointed at the real target function in the overlay.
- **What happened:** every stub decompiles to the same opaque two instructions —
  `rtlink_smart_vector_dispatch(0x281f); halt_baddata();` — with a "Bad instruction / Truncating
  control flow" warning, and `calls kind=callees` on the stub is likewise useless. There is no
  reference from the stub to its target, so the call graph is severed at every overlay boundary.
- **Workaround:** the stub *name* encodes the target: `OVLSTUB_<NN>_<OFFS>` -> `OVERLAY_<NN>::03a000
  + 0xOFFS`. So `OVLSTUB_20_0EB0` -> `OVERLAY_20::03aeb0`. I had to hand-compute that address for
  every single stub and then `decompile` it. It works but it is pure manual arithmetic, and it only
  works because a previous analyst named the stubs consistently.
- **Suggestion:** either (a) have `decompile`/`calls` follow the `OVLSTUB_*` naming convention and
  report the resolved overlay target, or (b) expose a small `resolve_overlay_stub` capability, or
  at minimum (c) mention the `OVLSTUB_<NN>_<OFFS>` -> `OVERLAY_<NN>::03a000+OFFS` rule in the
  tool description for `decompile`, since without it an agent can get stuck at the first thunk.

- **Second, smaller item:** 16-bit real-mode functions here pass args in AX/DX/BX plus the stack, and
  the decompiler's default guess renders those as bogus `in_AX`/`in_DX`/`in_BX` locals, silently
  mis-ordering the *stack* args too. The decompiled output looks plausible but is wrong — e.g.
  `surface_fill_rect` appeared to take `(color, h, desc...)` with no x/y at all. Only
  `disassemble` revealed `MOV AX,0xf1 / MOV DX,0x32 / MOV BX,0x4f`.
  `set_function_signature` with `parameters[].storage` fixed this perfectly and the callers then
  decompiled with correct literals — that tool is excellent. The friction is that nothing *warns*
  you the prototype is a guess. A hint in `decompile` output when a function has no committed
  prototype and the decompiler invented `in_<REG>` inputs would have saved a lot of cross-checking.
