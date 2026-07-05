package ebbex.ghidramcpserver.tools;

import java.util.List;
import java.util.Map;

import ebbex.ghidramcpserver.ProgramTool;
import ebbex.ghidramcpserver.util.Args;
import ebbex.ghidramcpserver.util.Decompilers;
import ebbex.ghidramcpserver.util.Locations;
import ebbex.ghidramcpserver.util.Results;
import ebbex.ghidramcpserver.util.Schemas;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import io.modelcontextprotocol.spec.McpSchema;

/** Decompile a function to C. */
public class DecompileTool implements ProgramTool {

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
				"function", Schemas.stringProp(
					"Function to decompile: a function name or an address inside it"),
				"functions", Map.of("type", "array",
					"description", "Decompile several at once (function names or addresses " +
						"inside them); max " + MAX_BATCH,
					"items", Map.of("type", "string")),
				"timeout_s", Schemas.intProp("Decompiler timeout in seconds (default " +
					DEFAULT_TIMEOUT + ")")));
	}

	@Override
	public boolean isReadOnly() {
		return true;
	}

	@Override
	public McpSchema.CallToolResult execute(Map<String, Object> args, Program program) {
		int timeout = Args.intArg(args, "timeout_s", DEFAULT_TIMEOUT);

		Object many = args.get("functions");
		if (many instanceof List<?> list && !list.isEmpty()) {
			StringBuilder sb = new StringBuilder();
			int n = Math.min(list.size(), MAX_BATCH);
			for (int i = 0; i < n; i++) {
				sb.append(decompileOne(program, String.valueOf(list.get(i)), timeout)).append("\n");
			}
			if (list.size() > MAX_BATCH) {
				sb.append("(").append(list.size() - MAX_BATCH)
						.append(" more not decompiled — cap is ").append(MAX_BATCH).append(")\n");
			}
			return Results.ok(sb.toString());
		}

		String functionRef = Args.stringArg(args, "function", null);
		if (functionRef == null) {
			return Results.error("'function' (a name or an address inside it), or a 'functions' " +
				"list, is required");
		}
		return Results.ok(decompileOne(program, functionRef, timeout));
	}

	private String decompileOne(Program program, String ref, int timeout) {
		Function function;
		try {
			function = Locations.findFunction(program, ref);
		}
		catch (Exception e) {
			return "// " + ref + ": " + e.getMessage();
		}
		DecompileResults results = decompilers.decompile(program, function, timeout);
		if (results != null && results.getDecompiledFunction() != null) {
			String c = results.getDecompiledFunction().getC();
			if (c != null && !c.isBlank()) {
				return c;
			}
		}
		String message = results == null ? "no result" : results.getErrorMessage();
		return "// Decompilation failed for " + function.getName() + ": " +
			(message == null || message.isBlank() ? "unknown" : message);
	}
}
