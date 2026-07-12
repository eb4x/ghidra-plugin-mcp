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

