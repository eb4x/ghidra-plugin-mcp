package ebbex.ghidramcpserver.tools;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.UnaryOperator;

import ebbex.ghidramcpserver.ProgramTool;
import ebbex.ghidramcpserver.util.Args;
import ebbex.ghidramcpserver.util.Locations;
import ebbex.ghidramcpserver.util.ProjectContext;
import ebbex.ghidramcpserver.util.Results;
import ebbex.ghidramcpserver.util.Schemas;
import ghidra.program.model.listing.Program;
import io.modelcontextprotocol.spec.McpSchema;

/**
 * Apply a list of edits to one program in a single call: fewer round-trips, one
 * save at the end, and (because the endpoint holds the program's write lock for
 * the whole call) no interleaving with other writers. Each edit is dispatched to
 * the matching single-edit tool; a failing edit is reported and the rest continue.
 */
public class BatchTool implements ProgramTool {

	private final Map<String, ProgramTool> ops;

	/** Dispatches to the same single-edit tool instances the endpoint registers. */
	public BatchTool(List<ProgramTool> editTools) {
		this.ops = new LinkedHashMap<>();
		for (ProgramTool tool : editTools) {
			ops.put(tool.name(), tool);
		}
	}

	@Override
	public String name() {
		return "batch";
	}

	@Override
	public String description() {
		return "Apply many edits to one program in a single call (e.g. a whole rename plan, or " +
			"deleting a set of bogus references found with xrefs). 'edits' is a list of objects, " +
			"each with an 'op' (" + String.join("|", ops.keySet()) + ") plus that op's arguments " +
			"(same as the standalone tool, minus 'program'). Edits run in order, continue on error, " +
			"and the program is saved once. 'function'/'location' NAMES are resolved against the " +
			"pre-batch state before any edit runs, so a plan may rename a function and keep " +
			"addressing later edits to it by the old name; a name that doesn't exist yet (created " +
			"by an earlier edit in the same batch) resolves when its edit runs.";
	}

	@Override
	public Map<String, Object> inputSchema() {
		return Map.of(
			"type", "object",
			"properties", Map.of(
				"edits", Map.of(
					"type", "array",
					"description", "Edits to apply in order; each is {op, ...op-args}",
					"items", Map.of(
						"type", "object",
						"properties", Map.of("op", Schemas.enumProp(
							"Which edit", List.of(ops.keySet().toArray(new String[0])))),
						"required", List.of("op")))),
			"required", List.of("edits"));
	}

	@Override
	public boolean isReadOnly() {
		return false;
	}

	@Override
	public boolean managesSave() {
		// dispatched tools each commit their own transaction; save once at the end
		return true;
	}

	@Override
	public McpSchema.CallToolResult execute(Map<String, Object> args, Program program)
			throws Exception {
		Object editsObj = args.get("edits");
		if (!(editsObj instanceof List<?> edits) || edits.isEmpty()) {
			return Results.error("'edits' must be a non-empty list");
		}

		// Resolve names against the pre-batch state for EVERY edit before running any: an
		// in-loop resolution would see edit 0's rename and break edit 1's old-name reference,
		// which is exactly the natural rename-then-annotate plan this exists to keep working.
		List<Map<String, Object>> pinnedEdits = new ArrayList<>(edits.size());
		for (Object raw : edits) {
			if (raw instanceof Map<?, ?> map) {
				@SuppressWarnings("unchecked")
				Map<String, Object> edit = (Map<String, Object>) map;
				pinnedEdits.add(pinNames(program, edit));
			}
			else {
				pinnedEdits.add(null);
			}
		}

		StringBuilder report = new StringBuilder();
		int ok = 0;
		int failed = 0;
		for (int i = 0; i < pinnedEdits.size(); i++) {
			Map<String, Object> edit = pinnedEdits.get(i);
			if (edit == null) {
				report.append("[").append(i).append("] ERROR: not an object\n");
				failed++;
				continue;
			}
			String op = Args.stringArg(edit, "op", null);
			ProgramTool tool = op == null ? null : ops.get(op);
			if (tool == null) {
				report.append("[").append(i).append("] ERROR: unknown op '").append(op)
						.append("' (expected ").append(ops.keySet()).append(")\n");
				failed++;
				continue;
			}
			McpSchema.CallToolResult result;
			try {
				result = tool.execute(edit, program);
			}
			catch (Exception e) {
				result = Results.error(op + " threw: " + e);
			}
			boolean isError = Boolean.TRUE.equals(result.isError());
			if (isError) {
				failed++;
			}
			else {
				ok++;
			}
			report.append("[").append(i).append("] ").append(isError ? "ERROR: " : "ok: ")
					.append(firstLine(result)).append('\n');
		}

		// Save once at the end, bounded so a big batch never holds the write lock for minutes
		// (see ProjectContext.saveSettled); a deferred save just annotates the report.
		boolean saved = ProjectContext.saveSettled(program);
		McpSchema.CallToolResult result = Results.ok(ok + " ok, " + failed + " failed:\n" + report);
		return saved ? result : Results.appendNote(result, ProjectContext.SAVE_DEFERRED_NOTE);
	}

	/**
	 * Rewrite 'function'/'location' NAME arguments to the addresses they resolve to right
	 * now — the pre-batch state the edit list was written from. A string already in address
	 * syntax is left alone (same resolution, nothing to protect), and a name that doesn't
	 * resolve yet is also left alone: it may name something an earlier edit in the batch
	 * creates, and otherwise it fails with the dispatched tool's own error.
	 */
	private static Map<String, Object> pinNames(Program program, Map<String, Object> edit) {
		Map<String, Object> pinned = new LinkedHashMap<>(edit);
		pin(pinned, "function",
			name -> Locations.findFunction(program, name).getEntryPoint().toString());
		pin(pinned, "location", name -> Locations.findLocation(program, name).toString());
		return pinned;
	}

	private static void pin(Map<String, Object> edit, String key, UnaryOperator<String> resolve) {
		if (!(edit.get(key) instanceof String value) || value.isBlank() ||
			Locations.isAddressSyntax(value)) {
			return;
		}
		try {
			edit.put(key, resolve.apply(value));
		}
		catch (RuntimeException e) {
			// Not resolvable against the current state — leave the name for the edit.
		}
	}

	private static String firstLine(McpSchema.CallToolResult result) {
		for (McpSchema.Content c : result.content()) {
			if (c instanceof McpSchema.TextContent text) {
				String t = text.text();
				int nl = t.indexOf('\n');
				return nl < 0 ? t : t.substring(0, nl);
			}
		}
		return "";
	}
}
