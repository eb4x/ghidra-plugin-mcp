package ebbex.ghidramcpserver.tools;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Set;

import ebbex.ghidramcpserver.ProgramTool;
import ebbex.ghidramcpserver.util.Args;
import ebbex.ghidramcpserver.util.Locations;
import ebbex.ghidramcpserver.util.Results;
import ebbex.ghidramcpserver.util.Schemas;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import io.modelcontextprotocol.spec.McpSchema;

/** Function-level call graph: the functions a function calls, or that call it. */
public class CallsTool implements ProgramTool {

	private static final List<String> KINDS = List.of("callees", "callers");
	private static final int DEFAULT_LIMIT = 100;

	@Override
	public String name() {
		return "calls";
	}

	@Override
	public String description() {
		return "List the functions called by a function (kind=callees) or that call it " +
			"(kind=callers), resolved at the function level (not raw references). Handy for " +
			"walking a call chain like fopen -> _openfile -> open. Paginated.";
	}

	@Override
	public Map<String, Object> inputSchema() {
		return Map.of(
			"type", "object",
			"properties", Map.of(
				"target", Schemas.stringProp("Function name or an address within the function"),
				"kind", Schemas.enumProp("Direction (default callees)", KINDS),
				"offset", Schemas.intProp("Skip this many (default 0)"),
				"limit", Schemas.intProp("Maximum to return (default " + DEFAULT_LIMIT + ")")),
			"required", List.of("target"));
	}

	@Override
	public boolean isReadOnly() {
		return true;
	}

	@Override
	public McpSchema.CallToolResult execute(Map<String, Object> args, Program program) {
		String target = Args.stringArg(args, "target", null);
		if (target == null) {
			return Results.error("target is required");
		}
		String kind = Args.stringArg(args, "kind", "callees");
		if (!KINDS.contains(kind)) {
			return Results.error("kind must be one of " + KINDS);
		}
		int offset = Math.max(0, Args.intArg(args, "offset", 0));
		int limit = Math.max(1, Args.intArg(args, "limit", DEFAULT_LIMIT));

		Function function = Locations.findFunction(program, target);
		Set<Function> related = kind.equals("callees")
				? function.getCalledFunctions(TaskMonitor.DUMMY)
				: function.getCallingFunctions(TaskMonitor.DUMMY);

		List<Function> sorted = new ArrayList<>(related);
		sorted.sort(Comparator.comparing(Function::getEntryPoint));

		List<String> window = new ArrayList<>();
		for (int i = offset; i < sorted.size() && window.size() < limit; i++) {
			Function f = sorted.get(i);
			window.add(f.getEntryPoint() + "  " + f.getName());
		}

		if (window.isEmpty()) {
			return Results.ok(function.getName() + " has no " + kind +
				(offset > 0 ? " at offset " + offset : ""));
		}
		return Results.ok(function.getName() + " " + kind + ":\n" + String.join("\n", window) +
			"\n" + Results.paginationFooter(window.size(), offset, sorted.size()));
	}
}
