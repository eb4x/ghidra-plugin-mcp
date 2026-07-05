package ebbex.ghidramcpserver.tools;

import java.util.List;
import java.util.Map;

import ebbex.ghidramcpserver.McpToolDef;
import ebbex.ghidramcpserver.util.Decompilers;
import ebbex.ghidramcpserver.util.ProgramContext;
import ebbex.ghidramcpserver.util.Results;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import io.modelcontextprotocol.spec.McpSchema;

/** Decompile a function to C. */
public class DecompileTool implements McpToolDef {

	private static final int DEFAULT_TIMEOUT = 30;
	private static final int MAX_BATCH = 12;

	private final Decompilers decompilers;

	public DecompileTool(Decompilers decompilers) {
		this.decompilers = decompilers;
	}

	@Override
	public String name() {
		return "decompile";
	}

	@Override
	public String description() {
		return "Decompile a function to C. Identify the function by name or by any address " +
			"inside it.";
	}

	@Override
	public Map<String, Object> inputSchema() {
		return Map.of(
			"type", "object",
			"properties", Map.of(
				"function", Results.stringProp(
					"Function to decompile: a name OR an address (alias: 'target'/'address')"),
				"address", Results.stringProp("Alias for 'function' — an address in the function"),
				"functions", Map.of("type", "array",
					"description", "Decompile several at once (names/addresses); max " + MAX_BATCH,
					"items", Map.of("type", "string")),
				"timeout_s", Results.intProp("Decompiler timeout in seconds (default " +
					DEFAULT_TIMEOUT + ")")));
	}

	@Override
	public boolean isReadOnly() {
		return true;
	}

	@Override
	public McpSchema.CallToolResult execute(Map<String, Object> args, Program program) {
		int timeout = Results.intArg(args, "timeout_s", DEFAULT_TIMEOUT);
		DecompInterface di = decompilers.get(program);

		Object many = args.get("functions");
		if (many instanceof List<?> list && !list.isEmpty()) {
			StringBuilder sb = new StringBuilder();
			int n = Math.min(list.size(), MAX_BATCH);
			for (int i = 0; i < n; i++) {
				sb.append(decompileOne(program, di, String.valueOf(list.get(i)), timeout))
						.append("\n");
			}
			if (list.size() > MAX_BATCH) {
				sb.append("(").append(list.size() - MAX_BATCH)
						.append(" more not decompiled — cap is ").append(MAX_BATCH).append(")\n");
			}
			return Results.ok(sb.toString());
		}

		String target = Results.locationArg(args);
		if (target == null) {
			return Results.error("a function (name or address), or a 'functions' list, is required");
		}
		return Results.ok(decompileOne(program, di, target, timeout));
	}

	private String decompileOne(Program program, DecompInterface di, String ref, int timeout) {
		Function function;
		try {
			function = ProgramContext.findFunction(program, ref);
		}
		catch (Exception e) {
			return "// " + ref + ": " + e.getMessage();
		}
		DecompileResults results = di.decompileFunction(function, timeout, TaskMonitor.DUMMY);
		if (results != null && results.getDecompiledFunction() != null) {
			String c = results.getDecompiledFunction().getC();
			if (c != null && !c.isBlank()) {
				return c;
			}
		}
		String message = results == null ? "no result" : results.getErrorMessage();
		if (message == null || message.isBlank()) {
			message = di.getLastMessage();
		}
		return "// Decompilation failed for " + function.getName() + ": " + message;
	}
}
