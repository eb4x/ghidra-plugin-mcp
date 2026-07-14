// Headless smoke test for the refactored two-group design. Exercises the
// application-level tools (project info, list, import) and the program tools
// (analyze + inspect/edit by path), verifying writes persist. Not shipped in
// the extension (excluded from buildExtension).
//@category MCP
import java.util.List;
import java.util.Map;
import java.util.concurrent.Callable;

import ebbex.ghidramcpserver.ApplicationLevelTool;
import ebbex.ghidramcpserver.ProgramTool;
import ebbex.ghidramcpserver.ToolRegistry;
import ebbex.ghidramcpserver.util.Decompilers;
import ebbex.ghidramcpserver.util.Locations;
import ebbex.ghidramcpserver.util.ProjectContext;
import ebbex.ghidramcpserver.util.Results;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.script.GhidraScript;
import ghidra.framework.main.AppInfo;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.Project;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.HighFunction;
import ghidra.util.task.TaskMonitor;
import io.modelcontextprotocol.spec.McpSchema;

public class McpToolSmokeScript extends GhidraScript {

	private List<ApplicationLevelTool> appTools;
	private List<ProgramTool> programTools;

	/** Tools that threw something other than a bad-argument error — never expected. */
	private int failures;

	@Override
	protected void run() throws Exception {
		Decompilers decompilers = new Decompilers();
		ProjectContext projectContext = new ProjectContext(decompilers);
		appTools = ToolRegistry.appTools(projectContext);
		programTools = ToolRegistry.programTools(decompilers, projectContext);

		Project project = state.getProject();
		println("=== project = " + project.getName() +
			"  | AppInfo.getActiveProject() = " + AppInfo.getActiveProject() + " ===");

		// ---- application-level tools ----
		app("get_application_info", Map.of(), project);
		app("read_log", Map.of("tail", 5), project);
		app("read_log", Map.of("tail", 20, "filter", "log"), project);
		app("import", Map.of("file", "/bin/ls", "folder", "/"), project);
		app("list_files", Map.of(), project);

		// manage_files on folders: a throwaway copy in /smoke-scratch, so the program the rest
		// of this script depends on (/ls) is never at risk.
		app("import", Map.of("file", "/bin/ls", "folder", "/smoke-scratch"), project);
		app("manage_files", Map.of("op", "delete", "path", "/"), project);
		app("manage_files", Map.of("op", "delete", "path", "/__no_such_folder__"), project);
		app("manage_files",
			Map.of("op", "move", "path", "/smoke-scratch", "dest_folder", "/smoke-scratch/sub"),
			project);
		app("manage_files", Map.of("op", "delete", "path", "/smoke-scratch"), project);
		app("manage_files", Map.of("op", "delete", "path", "/smoke-scratch", "recursive", true),
			project);
		app("list_files", Map.of(), project);

		// ---- open the imported program by its project path ----
		DomainFile df = project.getProjectData().getFile("/ls");
		if (df == null) {
			println("!! import did not create /ls");
			return;
		}
		Program program = (Program) df.getDomainObject(this, false, false, TaskMonitor.DUMMY);
		try {
			// ---- program tools ----
			prog("analyze", Map.of(), program);
			// analyze runs on a background thread (holding a program transaction) and
			// saves when done; wait for it to settle before editing or saving ourselves.
			waitForAnalysis(program);
			// One-shot path: an unknown analyzer name reports the available ones (exercises
			// arg parsing + the analyzer enumeration). The RTLink retrofit is the real user.
			prog("analyze", Map.of("analyzer", "No Such Analyzer"), program);
			prog("get_program_info", Map.of(), program);
			prog("list", Map.of("kind", "functions", "filter", "main", "limit", 3), program);
			prog("decompile", Map.of("function", "_init"), program);
			prog("decompile", Map.of("function", "_init", "dump_symbols", true), program);
			prog("decompile", Map.of("function", "_init", "dump_jumptables", true), program);
			prog("inspect", Map.of("location", "_init"), program);
			prog("xrefs", Map.of("location", "_init", "direction", "to", "limit", 5), program);
			prog("calls", Map.of("function", "_init", "kind", "callers", "limit", 5), program);

			// xrefs over a range, not a point: a function's 'from' references live on the
			// instructions that make them, so a point query on its name only sees the entry.
			prog("xrefs", Map.of("function", "_init", "direction", "from", "limit", 5), program);
			prog("xrefs", Map.of("function", "_init", "direction", "both", "limit", 5), program);
			// A range over one address space, with the other endpoint constrained by 'filter' —
			// the shape that answers "which references leave this segment?".
			String rangeMin = program.getMinAddress().toString();
			String rangeMax = program.getMinAddress().add(0x40000).toString();
			prog("xrefs", Map.of("min_address", rangeMin, "max_address", rangeMax,
				"direction", "from", "filter", "CALL", "limit", 5), program);
			// A target is required, and the three target forms are mutually exclusive.
			prog("xrefs", Map.of("direction", "from"), program);
			prog("xrefs", Map.of("location", "_init", "function", "_init"), program);
			prog("xrefs", Map.of("min_address", rangeMax, "max_address", rangeMin), program);
			// A range may not straddle two address spaces (the overlay case, caught explicitly).
			prog("xrefs", Map.of("min_address", rangeMin,
				"max_address", program.getMaxAddress().toString()), program);

			// create/clear kind=reference round-trip: the ref shows up in xrefs, then goes away.
			String refFrom = program.getMinAddress().toString();
			String refTo = program.getMaxAddress().toString();
			prog("create", Map.of("kind", "reference", "address", refFrom, "to_address", refTo,
				"ref_type", "computed_jump"), program);
			prog("xrefs", Map.of("location", refTo, "direction", "to", "limit", 5), program);
			// clear runs as a batch op too — deleting a set of references found by a range query
			// is the case that motivated it (one xrefs call, one batch, not ~1500 calls).
			prog("batch", Map.of("edits", List.of(
				Map.of("op", "clear", "kind", "reference", "address", refFrom,
					"to_address", refTo))), program);
			prog("clear", Map.of("kind", "reference", "address", refFrom, "to_address", refTo),
				program); // now gone: exercises the no-such-reference error

			// search_memory kind=instruction: substring of disassembled text.
			prog("search_memory", Map.of("kind", "instruction", "pattern", "PUSH", "limit", 5),
				program);

			// list user_only: the curated symbol map (drops FUN_/LAB_/DAT_ auto names).
			prog("list", Map.of("kind", "functions", "user_only", true, "limit", 5), program);
			prog("list", Map.of("kind", "symbols", "user_only", true, "limit", 5), program);

			// Husk enumeration + bookmarks: how an analysis failure is found without 2800 calls.
			prog("list", Map.of("kind", "functions", "max_body", 1, "limit", 5), program);
			prog("list", Map.of("kind", "bookmarks", "limit", 5), program);
			prog("list", Map.of("kind", "bookmarks", "filter", "error", "limit", 5), program);
			prog("list", Map.of("kind", "bookmarks", "max_body", 1), program); // wrong kind: refused

			// disassemble must SAY when the requested address holds no code, rather than
			// silently listing from the next instruction (which reads as "looked, found nothing").
			prog("disassemble", Map.of("address", program.getMaxAddress().toString(), "count", 2),
				program);

			// migrate: /ls -> itself is refused; a dry run against the same binary imported
			// twice is the honest exercise (everything already equal, nothing to write).
			prog("migrate", Map.of("source", "/ls"), program);
			prog("migrate", Map.of("source", "/__no_such_program__", "dry_run", true), program);

			// manage_files op=copy: the snapshot primitive (there is no undo — Ghidra drops its
			// undo history on every save, and every tool call here auto-saves).
			app("manage_files", Map.of("op", "copy", "path", "/ls", "dest_folder", "/backups",
				"new_name", "ls.snapshot"), project);
			app("list_files", Map.of("folder", "/backups"), project);
			app("manage_files", Map.of("op", "delete", "path", "/backups", "recursive", true),
				project);

			// manage_files delete on a file this script itself holds open: must refuse and
			// name the consumer (McpToolSmokeScript), not just say "open elsewhere".
			app("manage_files", Map.of("op", "delete", "path", "/ls"), project);
			// clear kind=local_variable: exercise the delete branch (not-found path is deterministic).
			prog("clear", Map.of("kind", "local_variable", "function", "_init",
				"variable_name", "__mcp_no_such_local__"), program);
			prog("rename", Map.of("kind", "function", "function", "_init",
				"new_name", "mcp_renamed_init"), program);

			// ---- set_data_type kind=struct: supplied layout + inferred ----
			Function structFn = null;
			String structVar = null;
			for (Function f : program.getFunctionManager().getFunctions(true)) {
				if (f.getParameterCount() > 0) {
					structFn = f;
					structVar = f.getParameter(0).getName();
					break;
				}
			}
			if (structFn == null) {
				println("!! no function with a parameter to exercise kind=struct");
			}
			else {
				prog("set_data_type", Map.of(
					"kind", "struct",
					"function", structFn.getName(),
					"variable_name", structVar,
					"struct", Map.of(
						"name", "mcp_smoke_struct",
						"size", 16,
						"fields", List.of(
							Map.of("offset", 0, "name", "first", "type", "uint"),
							Map.of("offset", 4, "name", "flag_a", "type", "byte", "bits", 3),
							Map.of("offset", 4, "name", "flag_b", "type", "byte", "bits", 5),
							Map.of("offset", 8, "name", "second", "type", "ushort")))),
					program);
				// Inferred path (omit 'struct'): a clean "could not infer" is expected here
				// unless structVar is dereferenced at offsets in structFn.
				prog("set_data_type", Map.of(
					"kind", "struct",
					"function", structFn.getName(),
					"variable_name", structVar), program);
				// manage_types op=rename_field on the struct just built (by name, then by offset).
				prog("manage_types", Map.of("op", "rename_field", "name", "mcp_smoke_struct",
					"field", "first", "new_name", "first_renamed"), program);
				prog("manage_types", Map.of("op", "rename_field", "name", "mcp_smoke_struct",
					"field", "0x8", "new_name", "second_renamed"), program);
			}

			// manage_types: not-found path (deterministic; no custom types guaranteed here).
			prog("manage_types", Map.of("op", "delete", "name", "__mcp_no_such_type__"), program);
			// batch: exercises the settle-then-save path (ProjectContext.saveSettled).
			prog("batch", Map.of("edits", List.of(
				Map.of("op", "rename", "kind", "function", "function", "mcp_renamed_init",
					"new_name", "mcp_batch_renamed"))), program);

			// set_function_signature structured mode: a param pinned to a register (custom storage).
			prog("set_function_signature", Map.of("function", "mcp_batch_renamed",
				"parameters", List.of(Map.of("name", "arg0", "type", "int", "storage", "EDI"))),
				program);

			// clear kind=label (create a scratch label then delete it) + the save tool.
			String scratchAddr = program.getMinAddress().toString();
			prog("create", Map.of("kind", "label", "address", scratchAddr,
				"name", "mcp_smoke_label"), program);
			prog("clear", Map.of("kind", "label", "address", scratchAddr,
				"name", "mcp_smoke_label"), program);
			prog("save", Map.of(), program);

			// create kind=label with a namespace must descend into the *function* namespace, not
			// create a plain namespace beside it. Decompiler jump-table overrides live at
			// <func>::override::jmp_<addr>, and nothing reads them if they land under global.
			Function init = Locations.findFunction(program, "mcp_batch_renamed");
			String entry = init.getEntryPoint().toString();
			prog("create", Map.of("kind", "label", "address", entry, "name", "switch",
				"namespace", init.getName() + "::override::jmp_" + entry), program);
			println(HighFunction.findOverrideSpace(init) != null
					? "override namespace resolved under the function"
					: "!! override namespace did NOT land under the function");

			df.save(TaskMonitor.DUMMY);
			prog("list", Map.of("kind", "functions", "filter", "mcp_renamed_init"), program);
		}
		finally {
			program.release(this);
		}

		// ---- reopen to confirm the rename persisted ----
		// Check the FINAL name: batch renamed mcp_renamed_init -> mcp_batch_renamed, so asserting
		// the intermediate name here reported "false" forever and read as a failure that wasn't.
		Program reopened = (Program) df.getDomainObject(this, false, false, TaskMonitor.DUMMY);
		try {
			boolean found = false;
			for (var f : reopened.getFunctionManager().getFunctions(true)) {
				if (f.getName().equals("mcp_batch_renamed")) {
					found = true;
					break;
				}
			}
			println(found
					? "=== rename persisted after reopen: true ==="
					: "!! rename did NOT persist after reopen");
			if (!found) {
				failures++;
			}
		}
		finally {
			reopened.release(this);
		}

		// Headless exits 0 even when a script aborts mid-run, so an aborted run reads as a pass
		// unless you look for this line. Grep for it — its absence is the failure signal.
		println(failures == 0
				? "=== SMOKE COMPLETE: all tools exercised, 0 unexpected exceptions ==="
				: "!! SMOKE COMPLETE WITH " + failures + " UNEXPECTED EXCEPTION(S)");
	}

	private void waitForAnalysis(Program program) throws Exception {
		AutoAnalysisManager mgr = AutoAnalysisManager.getAnalysisManager(program);
		long deadline = System.currentTimeMillis() + 180_000;
		while ((mgr.isAnalyzing() || program.getCurrentTransactionInfo() != null ||
			program.isChanged()) && System.currentTimeMillis() < deadline) {
			Thread.sleep(500);
		}
		println("=== analysis settled (analyzing=" + mgr.isAnalyzing() + ", changed=" +
			program.isChanged() + ") ===");
	}

	private void app(String name, Map<String, Object> args, Project project) {
		ApplicationLevelTool tool =
			appTools.stream().filter(t -> t.name().equals(name)).findFirst().orElseThrow();
		println("\n----- app:" + name + " " + args + " -----");
		print(call(() -> tool.execute(args, project), name));
	}

	private void prog(String name, Map<String, Object> args, Program program) {
		ProgramTool tool =
			programTools.stream().filter(t -> t.name().equals(name)).findFirst().orElseThrow();
		println("\n----- program:" + name + " " + args + " -----");
		print(call(() -> tool.execute(args, program), name));
	}

	/**
	 * Mirror {@code Endpoints}' exception handling: a tool that throws is an error <em>result</em>
	 * over MCP, not a crash. Calling execute() bare instead let one bad-argument case (migrate with
	 * a nonexistent source) abort the whole script mid-run — and headless still exited 0, so the
	 * run looked green while most of the tools went untested.
	 */
	private McpSchema.CallToolResult call(Callable<McpSchema.CallToolResult> body, String name) {
		try {
			return body.call();
		}
		catch (IllegalArgumentException e) {
			return Results.error(e.getMessage() != null ? e.getMessage() : e.toString());
		}
		catch (Exception e) {
			failures++;
			return Results.error(name + " threw " + e);
		}
	}

	private void print(McpSchema.CallToolResult result) {
		for (McpSchema.Content c : result.content()) {
			if (c instanceof McpSchema.TextContent t) {
				println(t.text());
			}
		}
		if (Boolean.TRUE.equals(result.isError())) {
			println("[isError=true]");
		}
	}
}
