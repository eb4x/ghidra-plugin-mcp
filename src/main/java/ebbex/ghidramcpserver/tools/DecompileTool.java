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
				"timeout_s", Results.intProp("Decompiler timeout in seconds (default " +
					DEFAULT_TIMEOUT + ")")));
	}

	@Override
	public boolean isReadOnly() {
		return true;
	}

	@Override
	public McpSchema.CallToolResult execute(Map<String, Object> args, Program program) {
		String target = Results.locationArg(args);
		if (target == null) {
			return Results.error("a function (name or address) is required");
		}
		int timeout = Results.intArg(args, "timeout_s", DEFAULT_TIMEOUT);
		Function function = ProgramContext.findFunction(program, target);

		DecompInterface di = decompilers.get(program);
		DecompileResults results = di.decompileFunction(function, timeout, TaskMonitor.DUMMY);
		if (results != null && results.getDecompiledFunction() != null) {
			String c = results.getDecompiledFunction().getC();
			if (c != null && !c.isBlank()) {
				return Results.ok(c);
			}
		}
		String message = results == null ? "no result" : results.getErrorMessage();
		if (message == null || message.isBlank()) {
			message = di.getLastMessage();
		}
		return Results.error("Decompilation failed for " + function.getName() + ": " + message);
	}
}
