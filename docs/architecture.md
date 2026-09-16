# Architecture

Request flow: MCP client → Jetty servlet (`McpHttpServer`) → per-tool call handler
(`Endpoints`) → tool implementation (`tools/`).

## Components

- **`MCPServerPlugin`** — an `ApplicationLevelPlugin` with `RELEASED` status, so it
  auto-installs into the Front End (project) tool and starts before any program is
  open. Owns the server lifecycle (`init()`/`dispose()`) and the *Tools → MCPServer*
  menu (Status / Restart). Port override: `-Dmcp.server.port=<port>`. Gotcha: a saved
  `FrontEndTool.xml` tool config can block auto-add of the plugin.
- **`McpHttpServer`** — one Jetty on one port; each `Endpoint` record is mounted as an
  independent MCP server at `/mcp/<path>`, so clients enable only the tool group they
  need. Also pins Jetty/Reactor/MCP-SDK loggers to WARN (they flood Ghidra's dev DEBUG
  log).
- **Two tool groups**, fixed lists in **`ToolRegistry`**:
  - `/mcp/application-level` — `ApplicationLevelTool` implementations (`tools/app/`),
    operate on the active `Project` (project lifecycle, import, file management, FID
    build). `requiresProject()` is how a tool opts out of the open-project gate —
    `read_log` and `manage_project` both must work before any project exists.
  - `/mcp/program` — `ProgramTool` implementations (`tools/`), operate on a `Program`.
    **`Endpoints`** augments every program tool's schema with a required `program`
    argument (a project file path like `/malware.exe`), resolves it through
    `ProjectContext`, and auto-saves after successful writes unless the tool's
    `managesSave()` is true (long-running tools like analyze that save themselves).
- **`util/ProjectContext`** — resolves programs by project path via
  `AppInfo.getActiveProject()`, caches opened programs for the server's lifetime,
  releases on dispose. Provides a per-path write lock: reads run lock-free and
  concurrent; writes to the same program serialize (protects `save()`).
- **`util/Analysis`** — the one place auto-analysis runs from: a single background
  worker that `analyze` and `import analyze=true` both queue onto (one program at a
  time, deduplicated by path; saves on completion). `Analysis.awaitIdle` is how the
  smoke script waits for queued work.
- **`util/Transactions.modify(...)`** — the single write path: every mutation runs on
  the Swing EDT inside a Ghidra transaction (undoable in the CodeBrowser; exceptions
  roll back).
- **`util/Decompilers`** — a lazy pool of `DecompInterface`s *per program* (each is a
  separate decompiler process), so parallel agent calls on one program don't
  serialize. Size: half the cores clamped to 2–8, override `-Dmcp.decompiler.pool=N`.
  `DecompileResults` are detached snapshots, safe to use after check-in.
- **`util/Results` / `util/Schemas` / `util/Args`** — result factories (+ shared
  pagination footer), JSON-schema fragments, and argument readers respectively.
- **`util/Locations`** — stateless name/address resolution (`parseAddress`,
  `findFunction`, `findLocation`) implementing the shared resolution order:
  address-shaped strings (`seg:off`, `0x`-hex) first, then indexed symbol lookup, bare
  hex last.

## Adding a program tool

Implement `ProgramTool` in `tools/`, register it in `ToolRegistry.programTools()`, and
add a call to the smoke script. `isReadOnly()` matters: it sets the MCP `readOnlyHint`
*and* decides whether the call takes the write lock + auto-save. Single-edit tools that
`batch` should dispatch to belong in the `editTools` list in `ToolRegistry`.
