# MCPServer — an MCP server embedded in Ghidra

A proof-of-concept Ghidra extension that runs a [Model Context Protocol](https://modelcontextprotocol.io)
server inside Ghidra. MCP clients (AI coding agents, etc.) connect over streamable
HTTP and inspect or edit the program currently open in the CodeBrowser.

The design goal is a **small, orthogonal tool set** — one tool per intention, with
`kind`/`target` enum parameters instead of dozens of near-duplicate tools — to keep
the client's context lean (cf. [bethington/ghidra-mcp#307](https://github.com/bethington/ghidra-mcp/issues/307)).

## Architecture

- Pure Java. The Ghidra plugin embeds the official **MCP Java SDK 2.0.0** and speaks
  MCP directly — no separate Python bridge.
- Transport: **streamable HTTP** at `http://127.0.0.1:8765/mcp`, served by an embedded
  **Jetty 12.1 (ee11 / jakarta.servlet 6.1)** container. No SSE.
- `MCPServerPlugin` (a `ProgramPlugin`) owns the server; it tracks the active program
  and starts/stops Jetty in `init()`/`dispose()`.
- Writes run on the Swing EDT inside a Ghidra transaction (`util/Transactions`), so
  every edit is undoable in the CodeBrowser.

## Tools

Two MCP endpoints on one port, so an agent loads only what it needs:

**`/mcp/application-level`** (the project): `get_application_info`, `list_files`,
`manage_files` (delete/rename/move), `import`, `fid_build`.

**`/mcp/program`** (a program, addressed by project path via a required `program` arg):
- Read/navigate: `get_program_info`, `list` (functions show caller counts, `sort=callers`
  finds hot leaf helpers), `inspect`, `decompile`, `disassemble`, `read_bytes`, `xrefs`,
  `calls` (call-graph callees/callers), `search_memory` (hits tagged with their function).
- Edit: `rename`, `set_comment`, `set_data_type`, `set_function_signature`,
  `define_types` (C structs/typedefs into the program), `clear` (clear code to undefined
  bytes = the "C" key), `create` (`kind=function|label|bookmark|instructions`;
  `instructions` re-disassembles = the "D" key), `analyze`, `fid_apply`, and `batch`
  (many edits in one call).

Notes:
- `set_function_signature` applies a full C prototype — return type, params, **and** the
  name — in one call (e.g. `FILE *fopen(const char *path, const char *mode)`; `const` is
  ignored, unknown types must be created first with `define_types`). Omit the signature to
  commit the decompiler's inferred prototype.
- `fid_build` ingests the named functions of one or more programs into a `.fidb`;
  `fid_apply` propagates those names (and signatures) to a same-language binary that shares
  code. Ghidra's own FID databases cover only Visual-Studio PE, so this is how you get FID
  for other toolchains.

Consolidation examples:
- `list` takes `kind=functions|symbols|strings|imports|exports|segments|data|namespaces`
  with `filter`/`offset`/`limit`.
- `rename` takes `target=function|label|data|parameter|local_variable`.
- `set_data_type` covers defining data, retyping variables/parameters, and return types.
- `set_comment` handles all five comment types (`eol|pre|post|plate|repeatable`).

## Build & install

Requires JDK 21+ and a Ghidra install. Point `GHIDRA_INSTALL_DIR` at it (e.g. in
`~/.gradle/gradle.properties`), then:

```bash
./gradlew buildExtension     # -> dist/ghidra_<ver>_<date>_MCPServer.zip
./gradlew installExtension   # extracts into ~/.config/ghidra/ghidra_<ver>/Extensions
```

Or install the zip via Ghidra's *File → Install Extensions*. Then launch Ghidra,
open a CodeBrowser, and enable the plugin under *File → Configure → Miscellaneous →
MCPServerPlugin*. The server starts automatically; open a program to give the tools
something to act on.

Port override: `-Dmcp.server.port=<port>` in Ghidra's launch properties.

### Tools menu

The plugin adds a **Tools → MCPServer** submenu:
- **Server Status** — shows the endpoint URL, running state, tool count, and the
  program currently in focus.
- **Restart Server** — stops and restarts the embedded server. Useful to retry the
  bind if the port was busy at startup (or you freed it since) without toggling the
  plugin. There is no separate Start/Stop: the server auto-starts with the plugin, and
  Restart doubles as "retry".

### Logging

The MCP SDK / Jetty / Reactor stack logs via SLF4J 2.0. The extension bundles
`log4j-slf4j2-impl` (matched to Ghidra's Log4j2 2.25.4) so those logs flow into
Ghidra's normal log instead of printing "No SLF4J providers found" NOP warnings at
startup. Only the bridge is bundled; `log4j-api`/`log4j-core` come from Ghidra.

## Connect a client

```bash
claude mcp add --transport http ghidra http://127.0.0.1:8765/mcp
```

## Develop in Eclipse (GhidraDev)

Install the GhidraDev plugin from `$GHIDRA_INSTALL_DIR/Extensions/Eclipse/GhidraDev/`,
then *GhidraDev → Import Ghidra Module Source* on this directory. *Debug As → Ghidra*
launches Ghidra with the project on the classpath (breakpoints work, no install round
trip). Third-party jars (MCP SDK, Jetty) come from `./gradlew copyDependencies` → `lib/`.

## Testing

`ghidra_scripts/McpToolSmokeScript.java` drives every tool against the current program.
Run it headless (it is deliberately **not** shipped in the extension zip):

```bash
mkdir -p /tmp/mcpsmoke && cp /bin/ls /tmp/ls.bin
$GHIDRA_INSTALL_DIR/support/analyzeHeadless /tmp/mcpsmoke smoke \
  -import /tmp/ls.bin -scriptPath ./ghidra_scripts -postScript McpToolSmokeScript
```

## Known limitations (PoC)

- One server per host port: if a second CodeBrowser opens, its plugin instance finds
  the port taken, logs a warning, and does not serve. (No shared singleton manager yet.)
- Operates only on the program active in the CodeBrowser (no multi-program targeting).
- A few functions can hit an upstream Ghidra decompiler error ("Unable to find unique
  hash for varnode", e.g. `main` in some coreutils binaries). `decompile` reports it as
  an error; other tools are unaffected.
- Deferred: byte patching / assembly, struct definition from C source, program
  open/close, and a config UI.
