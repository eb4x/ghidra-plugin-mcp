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
[archive/mcp-feedback.md](archive/mcp-feedback.md) (23 entries): the `decompile` coverage header,
`xrefs`/`calls` honest-zero caveats, the OVERLAY_24 analyzer root-cause, `read_log`, `xRam…` global
resolution, the bare-address rename hint, `inspect` Variables + thunk-status, `decompile dump_symbols`,
`clear kind=local_variable|label|function`, `manage_types op=rename_field`, `create kind=function
end_address`, namespaced-symbol resolution, the `set_function_signature` RETF hint, the bounded
deferring save + `save` tool, and the create-kind=thunk experiment (removed)._

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

## 2026-07-08 — gap — no custom (register) parameter storage; register-passed params un-nameable
- **Task:** pretty up `surface_fill_rect` (`1b9e:000a`), a 16-bit graphics primitive with a
  **mixed convention** — x in AX, y in DX, width in BX (registers), color/height/descriptor on
  the stack. Wanted to name all inputs, including the register-passed x/y/width.
- **Friction:** only the stack params surfaced as named variables. `width` (BX) and the segment
  (DX) could be reached via `rename kind=local_variable` on the decompiler's `in_BX`/`in_DX`
  aliases, but the **x coordinate (AX) never appears as a variable at all** — it is stored to a
  stack slot and consumed by-address into `surface_clip_rect`, so there is nothing to rename.
  `set_function_signature` can't help: a C prototype forces all params to stack storage, which is
  wrong here and would corrupt the (correct) decompile. There is no way to declare custom storage
  (`x @ AX, y @ DX, width @ BX`) over MCP.
- **Expected:** either a `set_function_signature` option to pin per-param storage (register or
  stack), or a `rename`/param tool that can create a named param bound to an input register.
- **Workaround:** renamed the reachable `in_BX`/`in_DX` aliases and documented the full register
  contract (AX=x, DX=y, BX=width) in the function's plate comment instead. Related: `surface_pixel_addr`
  (`1a4e:0008`) returns a **far pointer in DX:AX** (segment in DX = `desc[+6]`), but its recovered
  return type is plain `int`, so DX is invisible in C and the caller's `normalize_far_ptr(off, seg)`
  reads a phantom `in_DX`; a DX:AX / far-pointer return type would model it, but I only annotated it.
