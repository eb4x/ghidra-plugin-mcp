package ebbex.ghidramcpserver.tools;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
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
			"walking a call chain like fopen -> _openfile -> open. Thunks are resolved through: a " +
			"thunk carries its target's name, so kind=callers follows the thunk gate to the real " +
			"callers (marked 'via thunk ...') instead of reporting the gate as a same-named " +
			"self-call, and a thunk callee is annotated with its ultimate target. Paginated.";
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
		List<String> lines = kind.equals("callees")
				? calleeLines(function)
				: callerLines(function);

		List<String> window = new ArrayList<>();
		for (int i = offset; i < lines.size() && window.size() < limit; i++) {
			window.add(lines.get(i));
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
			Results.paginationFooter(window.size(), offset, lines.size()));
	}

	/**
	 * The functions that call {@code target}, resolved through thunks. A thunk is a call-graph
	 * edge, not a caller — and it carries {@code target}'s own name, so reporting it verbatim
	 * reads as "target is called by target". So a caller that is a thunk <em>to</em> target is
	 * replaced by <em>its</em> callers (through chains of thunks), each marked with the gate they
	 * came through. A thunk gate with no callers of its own is still shown, so it is never silently
	 * dropped.
	 */
	private static List<String> callerLines(Function target) {
		// function -> the thunk gate it was reached through (null for a direct caller). LinkedHashMap
		// so a function reached directly is not relabelled by a later thunk path; putIfAbsent keeps
		// the first, most-direct attribution.
		Map<Function, Function> callers = new LinkedHashMap<>();
		for (Function caller : target.getCallingFunctions(TaskMonitor.DUMMY)) {
			collectCallers(target, caller, null, callers, new java.util.HashSet<>());
		}
		return callers.entrySet().stream()
				.sorted(Map.Entry.comparingByKey(Comparator.comparing(Function::getEntryPoint)))
				.map(e -> render(e.getKey()) + gate(e.getValue()))
				.toList();
	}

	private static void collectCallers(Function target, Function caller, Function via,
			Map<Function, Function> out, Set<Function> seen) {
		if (!seen.add(caller)) {
			return; // guard against thunk/recursion cycles
		}
		if (caller.isThunk() && caller.getThunkedFunction(true) == target) {
			// caller is a gate INTO target; the real callers are the ones that call the gate.
			Set<Function> up = caller.getCallingFunctions(TaskMonitor.DUMMY);
			if (up.isEmpty()) {
				out.putIfAbsent(caller, null); // a gate nobody calls — surface it, don't drop it
				return;
			}
			for (Function u : up) {
				collectCallers(target, u, caller, out, seen);
			}
		}
		else {
			out.putIfAbsent(caller, via);
		}
	}

	/** The functions {@code function} calls, with any thunk callee annotated by its real target. */
	private static List<String> calleeLines(Function function) {
		List<Function> sorted = new ArrayList<>(function.getCalledFunctions(TaskMonitor.DUMMY));
		sorted.sort(Comparator.comparing(Function::getEntryPoint));
		return sorted.stream().map(CallsTool::render).toList();
	}

	/** A function as "entry  name", with "(thunk -> target @ addr)" when it is a thunk. */
	private static String render(Function function) {
		String line = function.getEntryPoint() + "  " + function.getName();
		if (function.isThunk()) {
			Function to = function.getThunkedFunction(true);
			line += "  (thunk -> " + to.getName() + " @ " + to.getEntryPoint() + ")";
		}
		return line;
	}

	private static String gate(Function via) {
		return via == null ? ""
				: "  (via thunk " + via.getName() + " @ " + via.getEntryPoint() + ")";
	}
}
