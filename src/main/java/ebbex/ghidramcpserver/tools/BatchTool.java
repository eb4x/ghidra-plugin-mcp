package ebbex.ghidramcpserver.tools;

import java.util.List;
import java.util.Map;

import ebbex.ghidramcpserver.ProgramTool;
import ebbex.ghidramcpserver.util.Args;
import ebbex.ghidramcpserver.util.Decompilers;
import ebbex.ghidramcpserver.util.Results;
import ebbex.ghidramcpserver.util.Schemas;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import io.modelcontextprotocol.spec.McpSchema;

/**
 * Apply a list of edits to one program in a single call: fewer round-trips, one
 * save at the end, and (because the endpoint holds the program's write lock for
 * the whole call) no interleaving with other writers. Each edit is dispatched to
 * the matching single-edit tool; a failing edit is reported and the rest continue.
 */
public class BatchTool implements ProgramTool {

	private final Map<String, ProgramTool> ops;

	public BatchTool(Decompilers decompilers) {
		this.ops = Map.of(
			"rename", new RenameTool(decompilers),
			"set_comment", new SetCommentTool(),
			"set_data_type", new SetDataTypeTool(decompilers),
			"set_function_signature", new SetFunctionSignatureTool(decompilers),
			"create", new CreateTool());
	}

	@Override
	public String name() {
		return "batch";
	}

	@Override
	public String description() {
		return "Apply many edits to one program in a single call (e.g. a whole rename plan). " +
			"'edits' is a list of objects, each with an 'op' (rename|set_comment|set_data_type|" +
			"set_function_signature|create) plus that op's arguments (same as the standalone tool, " +
			"minus 'program'). Edits run in order, continue on error, and the program is saved once.";
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

		StringBuilder report = new StringBuilder();
		int ok = 0;
		int failed = 0;
		for (int i = 0; i < edits.size(); i++) {
			if (!(edits.get(i) instanceof Map<?, ?> raw)) {
				report.append("[").append(i).append("] ERROR: not an object\n");
				failed++;
				continue;
			}
			@SuppressWarnings("unchecked")
			Map<String, Object> edit = (Map<String, Object>) raw;
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

		program.getDomainFile().save(TaskMonitor.DUMMY);
		return Results.ok(ok + " ok, " + failed + " failed:\n" + report);
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
