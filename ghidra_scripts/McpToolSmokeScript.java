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
import ebbex.ghidramcpserver.util.Analysis;
import ebbex.ghidramcpserver.util.Decompilers;
import ebbex.ghidramcpserver.util.Locations;
import ebbex.ghidramcpserver.util.ProjectContext;
import ebbex.ghidramcpserver.util.Results;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.script.GhidraScript;
import ghidra.framework.main.AppInfo;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.Project;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
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

		// The program everything below runs against is a fresh import of the same
		// compiled-on-the-spot target analyzeHeadless brought us up on — never a host
		// binary like /bin/ls, whose symbols vary by distro (Fedora's MiniDebugInfo has
		// main/_init, Ubuntu's stripped coreutils have neither).
		String targetFile = currentProgram.getExecutablePath();
		String targetName = new java.io.File(targetFile).getName();

		// ---- application-level tools ----
		app("get_application_info", Map.of(), project);
		app("read_log", Map.of("tail", 5), project);
		app("read_log", Map.of("tail", 20, "filter", "log"), project);
		app("import", Map.of("file", targetFile, "folder", "/"), project);
		app("list_files", Map.of(), project);

		// manage_project: only the paths that stay below the Swing boundary. Headless has no Front
		// End tool, and the project this script hand-carries into every app(...) call is the one
		// under test — actually opening or closing anything would invalidate it, the DomainFile and
		// Program opened below, and HeadlessAnalyzer's own teardown. So op=list_recent (which falls
		// back to the project's own manager when there is no Front End) plus both refusals.
		app("manage_project", Map.of("op", "list_recent"), project);
		app("manage_project",
			Map.of("op", "open", "path", "/__no_such_dir__", "name", "__no_such_project__"),
			project);
		// Must come back as a clean refusal, not AssertException from AppInfo.getFrontEndTool().
		app("manage_project", Map.of("op", "close"), project);
		app("manage_project", Map.of("op", "__no_such_op__"), project);

		// manage_files on folders: a throwaway copy in /smoke-scratch, so the program the rest
		// of this script depends on is never at risk.
		app("import", Map.of("file", targetFile, "folder", "/smoke-scratch"), project);
		app("manage_files", Map.of("op", "delete", "path", "/"), project);
		app("manage_files", Map.of("op", "delete", "path", "/__no_such_folder__"), project);
		app("manage_files",
			Map.of("op", "move", "path", "/smoke-scratch", "dest_folder", "/smoke-scratch/sub"),
			project);
		app("manage_files", Map.of("op", "delete", "path", "/smoke-scratch"), project);
		app("manage_files", Map.of("op", "delete", "path", "/smoke-scratch", "recursive", true),
			project);
		McpSchema.CallToolResult listing = app("list_files", Map.of(), project);

		// list_files marks programs whose processor language has moved on since they were
		// saved. Every program here was imported minutes ago by this very Ghidra, so the
		// count of marks must be zero: this cannot prove the check FINDS a stale program
		// (nothing hermetic is stale), but it does prove it does not invent one, which is
		// the failure that would matter — a false mark sends a caller off upgrading a
		// perfectly good program, and the upgrade is one-way.
		if (text(listing).contains("**") || text(listing).contains("??")) {
			failures++;
			println("!! list_files flagged a freshly imported program — '**' (needs a language " +
				"upgrade) or '??' (language version unreadable). Both are wrong here: these " +
				"programs were written minutes ago by this same Ghidra.");
		}

		// ---- raw-binary import: target.c is claimed by no loader, so the bare call must
		// fail WITH the raw-binary hint, and the loader/processor/base_address form must
		// load it at the requested base. Uses its own /raw folder so the /-path lookups
		// below stay untouched. "Raw Binary" (the display name) deliberately exercises the
		// name mapping — headless only takes the class name, BinaryLoader.
		String rawFile = new java.io.File(targetFile).getParent() + "/target.c";
		McpSchema.CallToolResult noLoader = app("import", Map.of("file", rawFile), project);
		if (!text(noLoader).contains("headerless")) {
			failures++;
			println("!! no-loader import is missing the raw-binary hint");
		}
		app("import", Map.of("file", rawFile, "folder", "/raw",
			"loader", "Raw Binary", "processor", "x86:LE:16:Real Mode",
			"cspec", "default", "base_address", "07c0:0000"), project);
		DomainFile rawDf = project.getProjectData().getFile("/raw/target.c");
		if (rawDf == null) {
			failures++;
			println("!! raw import did not create /raw/target.c");
		}
		else {
			Program rawProg = (Program) rawDf.getDomainObject(this, false, false, TaskMonitor.DUMMY);
			try {
				// BinaryLoader places the memory block at the base address without touching
				// the image-base property (which stays 0000:0000), so assert where the bytes
				// actually landed.
				println("raw import: language=" + rawProg.getLanguageID() + " memory starts at " +
					rawProg.getMinAddress());
				if (!"07c0:0000".equals(rawProg.getMinAddress().toString())) {
					failures++;
					println("!! base_address was not applied");
				}
				// This "binary" is C source text, so a function forced onto it is exactly the
				// bogus string-table function list kind=functions must tag TEXT.
				prog("create", Map.of("kind", "function", "address", "07c0:0000"), rawProg);
				McpSchema.CallToolResult textFns =
					prog("list", Map.of("kind", "functions"), rawProg);
				if (!text(textFns).contains("<-- TEXT:")) {
					failures++;
					println("!! a function over ASCII text was not tagged TEXT");
				}
			}
			finally {
				rawProg.release(this);
			}
		}
		// import options: a loader option set by its GUI name must land (BinaryLoader's
		// 'Block Name'), and a name the loader doesn't offer must refuse with the real list
		// rather than import with defaults.
		app("import", Map.of("file", rawFile, "folder", "/raw-opts", "loader", "BinaryLoader",
			"processor", "x86:LE:16:Real Mode", "options", Map.of("Block Name", "smokeblk")),
			project);
		DomainFile optsDf = project.getProjectData().getFile("/raw-opts/target.c");
		if (optsDf == null) {
			failures++;
			println("!! import with options did not create /raw-opts/target.c");
		}
		else {
			Program optsProg =
				(Program) optsDf.getDomainObject(this, false, false, TaskMonitor.DUMMY);
			try {
				if (optsProg.getMemory().getBlock("smokeblk") == null) {
					failures++;
					println("!! loader option 'Block Name' was not applied");
				}
			}
			finally {
				optsProg.release(this);
			}
		}
		McpSchema.CallToolResult badOption = app("import", Map.of("file", rawFile,
			"folder", "/raw-opts", "loader", "BinaryLoader", "processor", "x86:LE:16:Real Mode",
			"options", Map.of("__no_such_option__", "1")), project);
		if (!text(badOption).contains("is not an option of this loader") ||
			!text(badOption).contains("Block Name")) {
			failures++;
			println("!! unknown loader option was not refused with the option list");
		}
		app("manage_files", Map.of("op", "delete", "path", "/raw-opts", "recursive", true),
			project);
		// Refusals: the two dependency rules, then an unknown loader (lists the valid ones).
		app("import", Map.of("file", rawFile, "cspec", "default"), project);
		app("import", Map.of("file", rawFile, "base_address", "0x7c00"), project);
		app("import", Map.of("file", rawFile, "loader", "__no_such_loader__"), project);
		app("manage_files", Map.of("op", "delete", "path", "/raw", "recursive", true), project);

		// ---- open the imported program by its project path ----
		DomainFile df = project.getProjectData().getFile("/" + targetName);
		if (df == null) {
			println("!! import did not create /" + targetName);
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
			waitForAnalysis(program);
			prog("get_program_info", Map.of(), program);
			prog("list", Map.of("kind", "functions", "filter", "main", "limit", 3), program);
			prog("decompile", Map.of("function", "main"), program);
			prog("decompile", Map.of("function", "main", "dump_symbols", true), program);
			prog("decompile", Map.of("function", "main", "dump_jumptables", true), program);
			prog("inspect", Map.of("location", "main"), program);
			prog("xrefs", Map.of("location", "main", "direction", "to", "limit", 5), program);
			prog("calls", Map.of("function", "main", "kind", "callers", "limit", 5), program);
			// callees exercises the thunk-annotation path: ELF PLT stubs are thunk functions, so
			// a caller of library code lists thunks that get marked "(thunk -> target)".
			prog("calls", Map.of("function", "main", "kind", "callees", "limit", 10), program);

			// xrefs over a range, not a point: a function's 'from' references live on the
			// instructions that make them, so a point query on its name only sees the entry.
			prog("xrefs", Map.of("function", "main", "direction", "from", "limit", 5), program);
			prog("xrefs", Map.of("function", "main", "direction", "both", "limit", 5), program);
			// A range over one address space, with the other endpoint constrained by 'filter' —
			// the shape that answers "which references leave this segment?".
			String rangeMin = program.getMinAddress().toString();
			String rangeMax = program.getMinAddress().add(0x40000).toString();
			prog("xrefs", Map.of("min_address", rangeMin, "max_address", rangeMax,
				"direction", "from", "filter", "CALL", "limit", 5), program);
			// A target is required, and the three target forms are mutually exclusive.
			prog("xrefs", Map.of("direction", "from"), program);
			prog("xrefs", Map.of("location", "main", "function", "main"), program);
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
			// source=file: the ELF magic sits at file offset 0 and is loaded, so the hit must
			// come back as a file offset WITH its load address; instructions can't be searched
			// in a file and must refuse.
			McpSchema.CallToolResult fileHit = prog("search_memory",
				Map.of("pattern", "7f 45 4c 46", "source", "file", "limit", 3), program);
			if (!text(fileHit).contains("\n0x0  ->")) {
				failures++;
				println("!! source=file did not report offset 0x0 with its load address");
			}
			McpSchema.CallToolResult fileInsn = prog("search_memory",
				Map.of("pattern", "PUSH", "kind", "instruction", "source", "file"), program);
			if (!Boolean.TRUE.equals(fileInsn.isError())) {
				failures++;
				println("!! source=file with kind=instruction was not refused");
			}
			prog("search_memory", Map.of("kind", "instruction", "pattern", "PUSH", "limit", 5),
				program);

			// read_bytes, all three outcomes. The uninitialized case is the one worth pinning: a
			// BSS read has to say the image carries no bytes there — the fact the caller was
			// after — rather than fail the same way a wrong address does.
			MemoryBlock loaded = null;
			MemoryBlock bss = null;
			for (MemoryBlock b : program.getMemory().getBlocks()) {
				if (b.isInitialized() && loaded == null) {
					loaded = b;
				}
				if (!b.isInitialized() && bss == null) {
					bss = b;
				}
			}
			if (loaded != null) {
				prog("read_bytes", Map.of("address", loaded.getStart().toString(), "length", 32),
					program);
			}
			if (bss == null) {
				println("!! no uninitialized block in the target; read_bytes BSS case not covered");
			}
			else {
				println("(uninitialized block for the read_bytes case: " + bss.getName() + ")");
				prog("read_bytes", Map.of("address", bss.getStart().toString(), "length", 32),
					program);
				prog("inspect", Map.of("location", bss.getStart().toString()), program);
			}
			// Mapped nowhere: must not read as "uninitialized", and must not read as a bad length.
			prog("read_bytes", Map.of("address", "0x7fffff000000", "length", 16), program);
			// Starts readable and runs off the end: the dump must be footed with how much of the
			// request was actually satisfied, or a short dump reads as the whole answer.
			prog("read_bytes", Map.of("address", program.getMaxAddress().subtract(8).toString(),
				"length", 64), program);

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

			// Every separator the language defines must reach the caller. SLEIGH holds the ")"
			// of a disp(reg) operand as the separator AFTER the last operand, and a renderer
			// that only joins operands drops it (reported by ghidra-plugin-aeon: b.lbz
			// r5,0x4a(r6 ). x86-64 may define no trailing separator at all, so this reports
			// how many instructions it actually exercised rather than passing silently.
			checkTrailingSeparators(program);

			// create kind=memory_block. Runs after the .bss read_bytes case above, because the
			// split test carves .bss up and that case needs it whole.
			checkMemoryBlocks(program);

			// migrate: /ls -> itself is refused; a dry run against the same binary imported
			// twice is the honest exercise (everything already equal, nothing to write).
			prog("migrate", Map.of("source", "/ls.bin"), program);
			prog("migrate", Map.of("source", "/__no_such_program__", "dry_run", true), program);

			// manage_files op=copy: the snapshot primitive (there is no undo — Ghidra drops its
			// undo history on every save, and every tool call here auto-saves).
			app("manage_files", Map.of("op", "copy", "path", "/ls.bin", "dest_folder", "/backups",
				"new_name", "ls.snapshot"), project);
			app("list_files", Map.of("folder", "/backups"), project);
			app("manage_files", Map.of("op", "delete", "path", "/backups", "recursive", true),
				project);

			// manage_files delete on a file this script itself holds open: the script is not a
			// running tool, so the close-in-tools pass can't reach it — must refuse via the
			// cannot-close branch and name the consumer (McpToolSmokeScript).
			McpSchema.CallToolResult heldOpen =
				app("manage_files", Map.of("op", "delete", "path", "/ls.bin"), project);
			if (!text(heldOpen).contains("cannot close") ||
				!text(heldOpen).contains("McpToolSmokeScript")) {
				failures++;
				println("!! held-open delete refusal is missing the cannot-close consumer wording");
			}
			// and the on_dirty enum must validate before anything is touched.
			McpSchema.CallToolResult badOnDirty = app("manage_files",
				Map.of("op", "delete", "path", "/ls.bin", "on_dirty", "save"), project);
			if (!text(badOnDirty).contains("on_dirty must be one of")) {
				failures++;
				println("!! bad on_dirty was not refused");
			}
			// clear kind=local_variable: exercise the delete branch (not-found path is deterministic).
			prog("clear", Map.of("kind", "local_variable", "function", "main",
				"variable_name", "__mcp_no_such_local__"), program);
			prog("rename", Map.of("kind", "function", "function", "main",
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

				// manage_types op=set_field, walking the case that motivated it: widen a field,
				// then split it in two. Step 2 must report the undefined bytes it leaves behind,
				// or a half-finished split reads as a finished one.
				prog("manage_types", Map.of("op", "set_field", "name", "mcp_smoke_struct",
					"offset", "0x8", "type", "uint", "new_name", "widened"), program);
				prog("manage_types", Map.of("op", "set_field", "name", "mcp_smoke_struct",
					"offset", "0x8", "type", "byte[2]", "new_name", "split_lo"), program);
				prog("manage_types", Map.of("op", "set_field", "name", "mcp_smoke_struct",
					"offset", "0xa", "type", "byte[2]", "new_name", "split_hi"), program);
				// Refusals: past the end of the struct, and a type that doesn't parse.
				prog("manage_types", Map.of("op", "set_field", "name", "mcp_smoke_struct",
					"offset", "0x100", "type", "byte"), program);
				prog("manage_types", Map.of("op", "set_field", "name", "mcp_smoke_struct",
					"offset", "0x8", "type", "__no_such_type_t"), program);
				// Not a struct (or an ambiguous simple name) — either way it must refuse, not write.
				prog("manage_types", Map.of("op", "set_field", "name", "int",
					"offset", "0", "type", "byte"), program);
			}

			// The packed case, which is the one that matters: define_types parses C, and a struct
			// from C comes back packed, so this is the shape a real record actually has. set_field
			// must refuse it by default (offsets would be recomputed) and work with freeze_layout.
			prog("define_types", Map.of("source",
				"struct mcp_packed_rec { unsigned int head; unsigned char pad[8]; };"), program);
			prog("manage_types", Map.of("op", "set_field", "name", "mcp_packed_rec",
				"offset", "0x4", "type", "byte[4]", "new_name", "lo"), program); // refused: packed
			prog("manage_types", Map.of("op", "set_field", "name", "mcp_packed_rec",
				"offset", "0x4", "type", "byte[4]", "new_name", "lo",
				"freeze_layout", true), program);
			// Now unpacked, so the second half of the split needs no flag.
			prog("manage_types", Map.of("op", "set_field", "name", "mcp_packed_rec",
				"offset", "0x8", "type", "byte[4]", "new_name", "hi"), program);

			// Landing in the MIDDLE of a field, which is what happens whenever the caller's idea of
			// the layout is off (assuming a 4-byte int in a 16-bit program, say). Both sides of the
			// replaced field are orphaned, and the result has to name BOTH gaps — reporting only
			// the tail is how a split gets left half-finished while reading as complete.
			prog("define_types", Map.of("source",
				"struct mcp_midfield_rec { unsigned int head; unsigned char body[8]; };"), program);
			prog("manage_types", Map.of("op", "set_field", "name", "mcp_midfield_rec",
				"offset", "0x6", "type", "byte[2]", "new_name", "middle",
				"freeze_layout", true), program);

			// manage_types: not-found path (deterministic; no custom types guaranteed here).
			prog("manage_types", Map.of("op", "delete", "name", "__mcp_no_such_type__"), program);
			// batch: exercises the settle-then-save path (ProjectContext.saveSettled) and the
			// pre-batch name snapshot — the set_comment addresses the function by the name the
			// rename in the same batch just retired (the natural rename-then-annotate plan).
			McpSchema.CallToolResult pinBatch = prog("batch", Map.of("edits", List.of(
				Map.of("op", "rename", "kind", "function", "function", "mcp_renamed_init",
					"new_name", "mcp_batch_renamed"),
				Map.of("op", "set_comment", "function", "mcp_renamed_init", "kind", "plate",
					"comment", "annotated via the pre-rename name"))), program);
			if (!text(pinBatch).startsWith("2 ok, 0 failed")) {
				failures++;
				println("!! batch name snapshot: old-name edit after a rename did not succeed");
			}

			// create kind=functions_from_table: the target carries mcp_table, two pointers to
			// helper and mix — both already functions here, so the walk must wire a reference
			// from each slot and report both targets as existing (creation itself shares
			// kind=function's disassemble-first machinery, covered above).
			var tableSyms = program.getSymbolTable().getSymbols("mcp_table");
			if (!tableSyms.hasNext()) {
				failures++;
				println("!! smoke target has no mcp_table symbol");
			}
			else {
				String tableAddr = tableSyms.next().getAddress().toString();
				McpSchema.CallToolResult walked = prog("create",
					Map.of("kind", "functions_from_table", "address", tableAddr, "count", 2),
					program);
				if (!text(walked).contains("2 already existed")) {
					failures++;
					println("!! functions_from_table did not find both existing targets");
				}
				McpSchema.CallToolResult slotRefs = prog("xrefs",
					Map.of("location", "helper", "direction", "to", "limit", 20), program);
				if (!text(slotRefs).contains(tableAddr)) {
					failures++;
					println("!! no reference from the table slot to helper");
				}
				// count is never guessed from a terminator — omitting it must refuse.
				McpSchema.CallToolResult noCount = prog("create",
					Map.of("kind", "functions_from_table", "address", tableAddr), program);
				if (!text(noCount).contains("count")) {
					failures++;
					println("!! functions_from_table without count was not refused");
				}
			}

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

			// ---- FID round trip, bulk import, functions_at_labels ----
			// fid_build ingests this (named, analyzed) build; fid_apply must put those names back
			// on the stripped twin the smoke task compiled beside it, and the report has to say
			// WHICH functions it named — the whole point of the per-function output.
			String smokeDir = new java.io.File(targetFile).getParent();
			String fidb = smokeDir + "/smoke.fidb";
			new java.io.File(fidb).delete();
			McpSchema.CallToolResult built = app("fid_build",
				Map.of("fidb", fidb, "programs", List.of("/" + targetName), "detail", true),
				project);
			if (!text(built).contains("Per program")) {
				failures++;
				println("!! fid_build detail=true printed no per-program breakdown");
			}
			// Bulk import: one glob, two ELFs (the named build and its stripped twin), analysis
			// queued in the same call. The empty-glob and container cases ride along.
			app("import", Map.of("file", smokeDir + "/*.nomatch"), project);
			McpSchema.CallToolResult bulk = app("import",
				Map.of("file", smokeDir + "/*.bin", "folder", "/bulk", "analyze", true), project);
			if (!text(bulk).contains("Imported 2 program(s)")) {
				failures++;
				println("!! glob import did not report two programs");
			}
			// ar archive: no loader claims it, so it must be expanded member by member.
			McpSchema.CallToolResult archive = app("import",
				Map.of("file", smokeDir + "/smoke.a", "folder", "/bulk/archive"), project);
			if (!text(archive).contains("/bulk/archive/target.o")) {
				failures++;
				println("!! ar-archive import did not expand into its member");
			}
			if (!Analysis.awaitIdle(180_000)) {
				failures++;
				println("!! queued bulk analysis did not finish in time");
			}
			DomainFile strippedDf = project.getProjectData().getFile("/bulk/ls-stripped.bin");
			if (strippedDf == null) {
				failures++;
				println("!! bulk import did not create /bulk/ls-stripped.bin");
			}
			else {
				Program stripped =
					(Program) strippedDf.getDomainObject(this, false, false, TaskMonitor.DUMMY);
				try {
					println("stripped twin: analyzed=" + ghidra.program.util.GhidraProgramUtilities
							.isAnalyzed(stripped) + ", functions=" +
						stripped.getFunctionManager().getFunctionCount());
					McpSchema.CallToolResult applied =
						prog("fid_apply", Map.of("fidb", fidb, "score_threshold", 5), stripped);
					if (!text(applied).contains(" -> mix")) {
						failures++;
						println("!! fid_apply did not report naming mix on the stripped twin");
					}
				}
				finally {
					stripped.release(this);
				}
			}
			// functions_at_labels: deleting a function leaves its (imported) label behind, so the
			// sweep has exactly one thing to recreate — and must skip everything else.
			prog("clear", Map.of("kind", "function", "function", "helper"), program);
			McpSchema.CallToolResult swept =
				prog("create", Map.of("kind", "functions_at_labels"), program);
			if (!text(swept).contains("Created 1 function(s)") ||
				!text(swept).contains("helper @")) {
				failures++;
				println("!! functions_at_labels did not recreate helper (and only helper)");
			}
			prog("create", Map.of("kind", "function"), program); // address required for the rest
			// create kind=function on bytes nothing has decoded: CreateFunctionCmd alone makes a
			// silent 1-byte husk there, so the tool must disassemble first and report a real body.
			Function helperFn = null;
			for (Function f : program.getFunctionManager().getFunctions(true)) {
				if (f.getName().equals("helper")) {
					helperFn = f;
				}
			}
			if (helperFn == null) {
				failures++;
				println("!! helper is gone after functions_at_labels");
			}
			else {
				String helperAddr = helperFn.getEntryPoint().toString();
				int helperSize = (int) helperFn.getBody().getNumAddresses();
				prog("clear", Map.of("kind", "function", "function", "helper"), program);
				prog("clear", Map.of("kind", "code", "address", helperAddr, "length", helperSize),
					program);
				McpSchema.CallToolResult recreated = prog("create",
					Map.of("kind", "function", "address", helperAddr, "name", "helper"), program);
				if (!text(recreated).contains("disassembled") ||
					text(recreated).contains("HUSK") ||
					text(recreated).contains("body 1 bytes")) {
					failures++;
					println("!! create kind=function on undecoded bytes did not disassemble first");
				}
				// inspect must READ assumed register context — the one analyzer output that had
				// no MCP-side reading (the DS/DGROUP entry). Assert by setting a value directly
				// (there is deliberately no MCP write path for context) and reading it back.
				ghidra.program.model.listing.ProgramContext ctx = program.getProgramContext();
				ghidra.program.model.lang.Register gs = ctx.getRegister("GS");
				if (gs == null) {
					failures++;
					println("!! no GS register in this language — pick another for the context check");
				}
				else {
					Address helperEntry = program.getAddressFactory().getAddress(helperAddr);
					int ctxTx = program.startTransaction("smoke register context");
					try {
						ctx.setValue(gs, helperEntry, helperEntry,
							java.math.BigInteger.valueOf(0x2b));
					}
					finally {
						program.endTransaction(ctxTx, true);
					}
					McpSchema.CallToolResult inspected =
						prog("inspect", Map.of("location", "helper"), program);
					if (!text(inspected).contains("GS = 0x2b") ||
						!text(inspected).contains("asserted over")) {
						failures++;
						println("!! inspect did not report the asserted GS value with its range");
					}
				}
			}
			// list kind=undeclared_inputs: commit a WRONG (parameterless) prototype on helper —
			// its body reads EDI (the real first arg) into a LIVE computation (the int return),
			// so the decompiler materialises in_EDI and the sweep must list helper as an
			// offender with the [committed] tag. (A void return would not do: the whole body is
			// then dead code, and the EDI read is eliminated along with it.) This is the
			// enumeration for what the decompile header warns about one function at a time.
			prog("set_function_signature",
				Map.of("function", "helper", "signature", "int helper(void)"), program);
			prog("decompile", Map.of("function", "helper"), program);
			McpSchema.CallToolResult offenders = prog("list",
				Map.of("kind", "undeclared_inputs", "filter", "helper"), program);
			if (!text(offenders).contains("in_EDI") || !text(offenders).contains("[committed]")) {
				failures++;
				println("!! undeclared_inputs sweep did not flag helper's in_EDI");
			}
			prog("set_function_signature",
				Map.of("function", "helper", "signature", "int helper(int x)"), program);
			McpSchema.CallToolResult clean = prog("list",
				Map.of("kind", "undeclared_inputs", "filter", "helper"), program);
			if (!text(clean).contains("No undeclared_inputs")) {
				failures++;
				println("!! helper still flagged after its prototype was fixed");
			}

			// A signature full of unknown types must name ALL of them in one error (the parser
			// fails fast on the first; the tool re-parses with substitutions to collect the rest),
			// so one define_types call can create the lot instead of one round trip per type.
			McpSchema.CallToolResult unresolvedSig = prog("set_function_signature",
				Map.of("function", "helper", "signature",
					"mcp_undef_ret helper(mcp_undef_a * a, int b, mcp_undef_b c)"),
				program);
			String unresolvedText = text(unresolvedSig);
			if (!unresolvedText.contains("mcp_undef_ret") || !unresolvedText.contains("mcp_undef_a") ||
				!unresolvedText.contains("mcp_undef_b")) {
				failures++;
				println("!! unresolved-type error did not name all three unknown types");
			}
			// The advertised workaround must actually work: a forward declaration makes an
			// empty struct usable behind a pointer.
			prog("define_types", Map.of("source", "struct mcp_undef_a;"), program);
			McpSchema.CallToolResult forwardSig = prog("set_function_signature",
				Map.of("function", "helper", "signature", "int helper(mcp_undef_a * a)"),
				program);
			if (Boolean.TRUE.equals(forwardSig.isError())) {
				failures++;
				println("!! forward-declared struct was not usable behind a pointer");
			}
			prog("set_function_signature",
				Map.of("function", "helper", "signature", "int helper(int x)"), program);

			// noreturn: alone it flips only the flag (prototype untouched); a C 'noreturn' keyword
			// is rejected with a pointer to the flag; applying a signature with noreturn=false
			// clears it (ApplyFunctionSignatureCmd by itself never clears).
			Function noReturnFn = Locations.findFunction(program, "helper");
			String noReturnProto = noReturnFn.getSignature().getPrototypeString();
			prog("set_function_signature", Map.of("function", "helper", "noreturn", true), program);
			if (!noReturnFn.hasNoReturn() ||
				!noReturnProto.equals(noReturnFn.getSignature().getPrototypeString())) {
				failures++;
				println("!! noreturn=true alone did not set only the flag");
			}
			McpSchema.CallToolResult keywordSig = prog("set_function_signature",
				Map.of("function", "helper", "signature", "noreturn int helper(int x)"), program);
			if (!text(keywordSig).contains("noreturn=true")) {
				failures++;
				println("!! a C noreturn keyword was not pointed at the noreturn flag");
			}
			prog("set_function_signature", Map.of("function", "helper",
				"signature", "int helper(int x)", "noreturn", false), program);
			if (noReturnFn.hasNoReturn()) {
				failures++;
				println("!! signature + noreturn=false did not clear the flag");
			}

			// set_comment (never previously smoke-covered) + list kind=comments: write a plate
			// comment, then find it by TEXT without knowing the address — the query that used to
			// require decompiling every candidate function.
			prog("set_comment", Map.of("function", "helper", "kind", "plate",
				"comment", "mcp smoke needle:\nsecond line"), program);
			McpSchema.CallToolResult comments = prog("list",
				Map.of("kind", "comments", "filter", "smoke needle"), program);
			if (!text(comments).contains("[plate]") ||
				!text(comments).contains("mcp smoke needle:\\nsecond line")) {
				failures++;
				println("!! list kind=comments did not find the plate comment by text");
			}
			// The min/max_address scoping: a range that excludes helper must not find it.
			McpSchema.CallToolResult scoped = prog("list",
				Map.of("kind", "comments", "filter", "smoke needle",
					"min_address", program.getMaxAddress().toString()), program);
			if (!text(scoped).contains("No comments")) {
				failures++;
				println("!! list kind=comments range scoping did not exclude the comment");
			}
			// full=true must return an over-300-char comment untruncated (the 20-of-24 cost in
			// the dwelling->settlement rename: every long comment needed a separate inspect).
			String longText = "mcp long needle " + "x".repeat(400);
			prog("set_comment", Map.of("function", "helper", "kind", "pre",
				"comment", longText), program);
			McpSchema.CallToolResult truncated = prog("list",
				Map.of("kind", "comments", "filter", "long needle"), program);
			McpSchema.CallToolResult full = prog("list",
				Map.of("kind", "comments", "filter", "long needle", "full", true), program);
			if (!text(truncated).contains("[truncated") || !text(full).contains(longText) ||
				text(full).contains("[truncated")) {
				failures++;
				println("!! list kind=comments full=true did not skip truncation");
			}
			prog("list", Map.of("kind", "functions", "full", true), program); // gated: comments only
			prog("set_comment", Map.of("function", "helper", "kind", "pre", "comment", ""),
				program);
			prog("set_comment", Map.of("function", "helper", "kind", "plate", "comment", ""),
				program);

			// rename kind=function must absorb a same-named SECONDARY label at the entry (what a
			// FID pass leaves behind) instead of failing "already exists at this address".
			if (helperFn != null) {
				String helperAddr = helperFn.getEntryPoint().toString();
				prog("create", Map.of("kind", "label", "address", helperAddr,
					"name", "mcp_secondary"), program);
				McpSchema.CallToolResult absorbed = prog("rename",
					Map.of("kind", "function", "function", "helper", "new_name", "mcp_secondary"),
					program);
				if (!text(absorbed).contains("absorbed")) {
					failures++;
					println("!! rename kind=function did not absorb the secondary label");
				}
				prog("rename", Map.of("kind", "function", "function", "mcp_secondary",
					"new_name", "helper"), program);
			}
			// fid_build's name policy: on the stripped twin the five names fid_apply stamped are
			// SourceType.ANALYSIS and must be filtered by default (the ELF loader's own four —
			// entry, _DT_INIT, _FINI_0, _DT_FINI — are IMPORTED and stay); with
			// include_analysis_names=true nothing is filtered. 'exclude' must drop exactly 'mix'.
			String fidb2 = smokeDir + "/smoke2.fidb";
			new java.io.File(fidb2).delete();
			McpSchema.CallToolResult guesses = app("fid_build",
				Map.of("fidb", fidb2, "programs", List.of("/bulk/ls-stripped.bin")), project);
			if (!text(guesses).contains("5 analyzer-named or excluded")) {
				failures++;
				println("!! fid_build did not filter the five fid_apply-made names by default");
			}
			new java.io.File(fidb2).delete();
			McpSchema.CallToolResult included = app("fid_build",
				Map.of("fidb", fidb2, "programs", List.of("/bulk/ls-stripped.bin"),
					"include_analysis_names", true), project);
			if (!text(included).contains("0 excluded by name")) {
				failures++;
				println("!! fid_build include_analysis_names=true still filtered names");
			}
			new java.io.File(fidb2).delete();
			app("fid_build", Map.of("fidb", fidb2, "programs", List.of("/" + targetName),
				"exclude", "[unclosed"), project);
			McpSchema.CallToolResult excluded = app("fid_build",
				Map.of("fidb", fidb2, "programs", List.of("/" + targetName), "exclude", "^mix$",
					"detail", true), project);
			if (!text(excluded).contains("Ingested 8 of") ||
				!text(excluded).contains("1 analyzer-named or excluded")) {
				failures++;
				println("!! fid_build exclude='^mix$' did not drop exactly one function");
			}
			app("manage_files", Map.of("op", "delete", "path", "/bulk", "recursive", true),
				project);
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
		// The analyze tool returns before its background thread has opened its
		// transaction, so a single quiet sample races a slow thread start (the tool
		// thread then blocks batch calls mid-script and outlives the run; bit us on a
		// loaded CI runner). Only trust quiet that lasts: 8 consecutive samples.
		int quiet = 0;
		while (quiet < 8 && System.currentTimeMillis() < deadline) {
			boolean busy = mgr.isAnalyzing() || program.getCurrentTransactionInfo() != null ||
				program.isChanged();
			quiet = busy ? 0 : quiet + 1;
			Thread.sleep(500);
		}
		println("=== analysis settled (analyzing=" + mgr.isAnalyzing() + ", changed=" +
			program.isChanged() + ") ===");
	}

	private McpSchema.CallToolResult app(String name, Map<String, Object> args, Project project) {
		ApplicationLevelTool tool =
			appTools.stream().filter(t -> t.name().equals(name)).findFirst().orElseThrow();
		println("\n----- app:" + name + " " + args + " -----");
		McpSchema.CallToolResult result = call(() -> tool.execute(args, project), name);
		print(result);
		return result;
	}

	/**
	 * create kind=memory_block: the block carries the file's real bytes, and every refusal the
	 * overlap rules promise actually refuses. The memory map has no undo in the live server, so
	 * the refusals matter as much as the creation — each one is a rewrite that did not happen.
	 */
	private void checkMemoryBlocks(Program program) {
		// A free range well past the image: no overlap, so no split needed. file_offset 0 is the
		// ELF header, whose first four bytes are known, which is what makes this a real check
		// that the block is backed by the file rather than by zeroes.
		String free = "0x50000000";
		prog("create", Map.of("kind", "memory_block", "address", free, "name", "smoke_filebytes",
			"length", "0x40", "file_offset", 0), program);
		McpSchema.CallToolResult bytes =
			prog("read_bytes", Map.of("address", free, "length", 4), program);
		if (!text(bytes).toLowerCase().contains("7f 45 4c 46")) {
			failures++;
			println("!! memory_block did not expose the imported file's bytes (expected the ELF " +
				"magic 7f 45 4c 46 at file offset 0)");
		}

		// Same range again: an initialized block is never overwritten, whatever overlap says.
		McpSchema.CallToolResult onInitialized = prog("create", Map.of("kind", "memory_block",
			"address", free, "name", "smoke_clobber", "length", "0x10", "file_offset", 0,
			"overlap", "split"), program);
		if (!text(onInitialized).contains("already has bytes")) {
			failures++;
			println("!! memory_block overwrote, or failed to explain, a range in an initialized block");
		}

		// An uninitialized block, no overlap= given: refused, and the refusal must name the way
		// forward rather than just saying no.
		MemoryBlock bss = program.getMemory().getBlock(".bss");
		if (bss == null || bss.getEnd().subtract(bss.getStart()) < 3) {
			println("(no .bss of usable size; skipping the split cases)");
			return;
		}
		Address inside = bss.getStart().add(2);
		McpSchema.CallToolResult refused = prog("create", Map.of("kind", "memory_block",
			"address", inside.toString(), "name", "smoke_split", "length", 2, "file_offset", 0),
			program);
		if (!text(refused).contains("overlap=split")) {
			failures++;
			println("!! memory_block did not refuse an uninitialized overlap with a way forward");
		}

		// The carve itself: remnants either side, keeping .bss's name and uninitialized state.
		prog("create", Map.of("kind", "memory_block", "address", inside.toString(),
			"name", "smoke_split", "length", 2, "file_offset", 0, "overlap", "split"), program);
		MemoryBlock head = program.getMemory().getBlock(".bss");
		MemoryBlock carved = program.getMemory().getBlock(inside);
		MemoryBlock tail = program.getMemory().getBlock(".bss.1");
		if (carved == null || !"smoke_split".equals(carved.getName()) || !carved.isInitialized()) {
			failures++;
			println("!! the carved range did not become an initialized smoke_split block");
		}
		if (head == null || head.isInitialized() || head.getEnd().compareTo(inside) >= 0) {
			failures++;
			println("!! the head remnant lost its name, its bytes-free state, or its range");
		}
		if (tail == null || tail.isInitialized()) {
			failures++;
			println("!! the tail remnant is missing or is no longer uninitialized (expected .bss.1)");
		}
	}

	/**
	 * Disassemble {@code main} and confirm that every instruction whose language defines a
	 * trailing separator has it in the listing. Vacuous on a language that defines none — it
	 * says so rather than reporting a pass it did not earn.
	 */
	private void checkTrailingSeparators(Program program) {
		Function main = Locations.findFunction(program, "main");
		String[] lines = text(prog("disassemble", Map.of("function", "main"), program)).split("\n");
		int exercised = 0;
		for (Instruction instruction : program.getListing().getInstructions(main.getBody(), true)) {
			String tail = instruction.getSeparator(instruction.getNumOperands());
			if (tail == null || tail.isBlank()) {
				continue;
			}
			exercised++;
			String address = instruction.getAddress().toString();
			boolean intact = false;
			for (String line : lines) {
				if (line.startsWith(address) && line.stripTrailing().endsWith(tail)) {
					intact = true;
					break;
				}
			}
			if (!intact) {
				failures++;
				println("!! disassemble dropped the trailing separator '" + tail + "' at " + address);
			}
		}
		println("trailing-separator check: " + exercised + " instruction(s) in main define one");
	}

	private McpSchema.CallToolResult prog(String name, Map<String, Object> args, Program program) {
		ProgramTool tool =
			programTools.stream().filter(t -> t.name().equals(name)).findFirst().orElseThrow();
		println("\n----- program:" + name + " " + args + " -----");
		McpSchema.CallToolResult result = call(() -> tool.execute(args, program), name);
		print(result);
		return result;
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

	private static String text(McpSchema.CallToolResult result) {
		StringBuilder sb = new StringBuilder();
		for (McpSchema.Content c : result.content()) {
			if (c instanceof McpSchema.TextContent t) {
				sb.append(t.text());
			}
		}
		return sb.toString();
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
