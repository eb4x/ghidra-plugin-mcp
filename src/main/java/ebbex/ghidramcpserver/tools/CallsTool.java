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
				"function", Schemas.stringProp("Function name or an address inside it"),
				"kind", Schemas.enumProp("Direction (default callees)", KINDS),
				"offset", Schemas.intProp("Skip this many (default 0)"),
				"limit", Schemas.intProp("Maximum to return (default " + DEFAULT_LIMIT + ")")),
			"required", List.of("function"));
	}

	@Override
	public boolean isReadOnly() {
		return true;
	}

	@Override
	public McpSchema.CallToolResult execute(Map<String, Object> args, Program program) {
		String functionRef = Args.stringArg(args, "function", null);
		if (functionRef == null) {
			return Results.error("'function' (a name or an address inside it) is required");
		}
		String kind = Args.stringArg(args, "kind", "callees");
		if (!KINDS.contains(kind)) {
			return Results.error("kind must be one of " + KINDS);
		}
		int offset = Math.max(0, Args.intArg(args, "offset", 0));
		int limit = Math.max(1, Args.intArg(args, "limit", DEFAULT_LIMIT));

		Function function = Locations.findFunction(program, functionRef);
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

		if (window.isEmpty() && offset == 0) {
			// A bare zero for callers is ambiguous: calls resolved through jump-table/far-call
			// dispatch or register-indirect targets never become function-level call edges, so
			// zero callers is not proof the function is uncalled.
			if (kind.equals("callers")) {
				return Results.ok(function.getName() + " has no callers.\nNote: Ghidra does not " +
					"track unresolved computed/indirect calls (jump-table/far-call dispatch, " +
					"register-indirect). Zero callers is NOT proof it is uncalled — confirm by " +
					"searching the raw call encoding with search_memory kind=bytes.");
			}
			return Results.ok(function.getName() + " has no " + kind);
		}
		return Results.ok(function.getName() + " " + kind + ":\n" + String.join("\n", window) +
			(window.isEmpty() ? "" : "\n") +
			Results.paginationFooter(window.size(), offset, sorted.size()));
	}
}
