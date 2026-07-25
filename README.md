# ghidra-plugin-mcp - an MCP server embedded in Ghidra

A [Ghidra](https://github.com/NationalSecurityAgency/ghidra) extension that
runs a [Model Context Protocol](https://modelcontextprotocol.io) server
*inside* Ghidra. MCP clients (AI coding agents, etc.) connect over streamable
HTTP to manage the Ghidra project and inspect or edit its programs.

> The tools that build the tools that builds the tool.

## AI slop: fork it, don't send patches

This is AI slop at its finest. The lines of code are **ALL** AI-generated. I
have no opinions on the code, I've barely read any of it, and I have no idea
which direction it should take. I decided on the base technology and answered
some basic questions, then had agents leave feedback, and acted as a liaison
between the agents and this plugin.

Heck even this README is mostly an AI summary.

The source is here for anyone to fork and use as their own starter plugin -
[Apache-2.0](LICENSE). But this is not an open-source *project*: I'm not
considering contributions, and there is no issue triage or roadmap.

## Why this exists

This project exists to ease development of **viceroy**, a "modern"
reimplementation of *Sid Meier's Colonization*. This server and its sibling
[ghidra-plugin-rtlink](https://github.com/eb4x/ghidra-plugin-rtlink) let
agents drive Ghidra, and what Ghidra recovers from the original `VICEROY.EXE`
informs viceroy's development.

The viceroy RE work started on
[bethington/ghidra-mcp](https://github.com/bethington/ghidra-mcp). Then I read
[issue #307](https://github.com/bethington/ghidra-mcp/issues/307) - tool
proliferation eating the agent's context, a deprecated SSE transport,
auto-closed tickets, user issues rewritten by AI - and realized I might be
using a tool written by a clown. I figured I could be my own clown and have
the AI write a new MCP from scratch.

This server is, more or less, that issue's recommendation list implemented:

- a **small, orthogonal tool set** - one tool per intention, with `kind`/`op`
  enum parameters instead of dozens of near-duplicate tools, keeping the
  client's context lean
- **streamable HTTP**, no SSE
- MCP served **from inside the Ghidra extension** - pure Java on the official
  MCP Java SDK, no separate Python bridge process

## The dogfooding loop

What keeps the tool set small while it improves is that its only real user is
also its test bench. The viceroy and ghidra-plugin-rtlink projects run all of
its Ghidra work through this server, and every agent doing that work is
required to log friction - missing capabilities, counter-intuitive arguments,
output that fights the caller - in
[`docs/mcp-feedback.md`](docs/mcp-feedback.md), in this repo, where the fixes
land.

The open entries are the backlog. When a tool grows, the default fix is
extending an existing tool's `kind`/`op` enum, not adding a new tool - so
capability goes up while the tool count doesn't. Resolved entries move to
[`docs/archive/mcp-feedback.md`](docs/archive/mcp-feedback.md) with the fixing
commits cited; each one was reproduced, fixed, and re-verified against the
live server (40+ archived so far). The semantic version in
`version.properties` is bumped in the same commit as the change, and
`GET /version` reports the serving build's version, commit and build time - so
an agent can confirm a restart actually loaded the fix it asked for.

## Architecture

- The **MCP Java SDK** serves at `http://127.0.0.1:8765/mcp/...` from an
  embedded **Jetty 12.1 (ee11 / jakarta.servlet 6.1)** container.
- `MCPServerPlugin` is an `ApplicationLevelPlugin`: it auto-installs into the
  Front End (project) tool and serves as soon as Ghidra is up, before any
  program is open. Programs are addressed by project path, so one server
  covers the whole project.
- Writes run on the Swing EDT inside a Ghidra transaction
  (`util/Transactions`), so every edit is undoable in the CodeBrowser, and the
  program is saved after each successful mutating call.
- Decompilation runs against a per-program pool of decompiler processes, so
  parallel agent calls don't serialize.

## Tools

Two MCP endpoints on one port, so an agent loads only what it needs:
**`/mcp/application-level`** manages the project (import, file management,
FID database building); **`/mcp/program`** works on a program, addressed by
its project path - decompile, disassemble, xrefs, call graphs, memory search,
DOS syscall resolution on the read side; renames, comments, types, function
signatures, batched edits on the write side.

A niche capability worth calling out: `fid_build`/`fid_apply` build a FID
database from named functions and propagate them to same-language binaries
that share code - Ghidra's own FID databases cover only Visual-Studio PE, so
this is how you get FID for other toolchains.

The tool schemas are self-describing over MCP; the conventions behind them
live in [CLAUDE.md](CLAUDE.md).

## Build & install

Prebuilt zips for official Ghidra releases are on the
[releases page](https://github.com/eb4x/ghidra-plugin-mcp/releases) - download
the zip matching your Ghidra version and install it through Ghidra's
*File → Install Extensions*.

To build yourself: JDK 21+ and two paths in a gitignored, project-local
`gradle.properties`:

- `GHIDRA_INSTALL_DIR` - an *extracted* Ghidra install, used only at build
  time (its `support/buildExtension.gradle` and API jars)
- `GHIDRA_USER_EXTENSIONS_DIR` - the running Ghidra's user `Extensions/`
  directory, where `installExtension` deploys the built extension

```bash
./gradlew buildExtension     # -> dist/ghidra_<ver>_<date>_MCPServer.zip
./gradlew installExtension   # deploy the zip into the Ghidra install + user Extensions dir
./gradlew copyDependencies   # refresh third-party jars in lib/ (Eclipse/GhidraDev classpath)
./gradlew smokeTest          # drive every tool headless against a freshly compiled tiny ELF
```

Restart Ghidra to load the new build (confirm with `GET /version`).

### Tools menu

The plugin adds a **Tools → MCPServer** submenu:
- **Server Status** - shows the endpoint URL, running state, and tool count.
- **Restart Server** - stops and restarts the embedded server. Useful to
  retry the bind if the port was busy at startup (or you freed it since)
  without toggling the plugin. There is no separate Start/Stop: the server
  auto-starts with the plugin, and Restart doubles as "retry".

### Logging

The MCP SDK / Jetty / Reactor stack logs via SLF4J 2.0. The extension bundles
`log4j-slf4j2-impl` (matched to Ghidra's Log4j2) so those logs flow into
Ghidra's normal log instead of printing "No SLF4J providers found" NOP
warnings at startup. Only the bridge is bundled; `log4j-api`/`log4j-core`
come from Ghidra.

## Connect a client

```bash
claude mcp add --transport http ghidra-program http://127.0.0.1:8765/mcp/program
claude mcp add --transport http ghidra-application-level http://127.0.0.1:8765/mcp/application-level
```

## Known limitations

- One server per host port: if the port is taken at startup (e.g. a second
  Ghidra instance), the plugin logs a warning and does not serve - free the
  port and use Tools → MCPServer → Restart Server, or set `-Dmcp.server.port`.
- A few functions can hit an upstream Ghidra decompiler error ("Unable to
  find unique hash for varnode", e.g. `main` in some coreutils binaries).
  `decompile` reports it as an error; other tools are unaffected.
- Deferred: byte patching / assembly, project open/close, and a config UI.
