package ebbex.ghidramcpserver.tools;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import ebbex.ghidramcpserver.McpToolDef;
import ebbex.ghidramcpserver.util.ProgramContext;
import ebbex.ghidramcpserver.util.Results;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.ReferenceManager;
import io.modelcontextprotocol.spec.McpSchema;

/** Cross-references to and/or from an address, symbol, or function. */
public class XrefsTool implements McpToolDef {

	private static final List<String> DIRECTIONS = List.of("to", "from", "both");
	private static final int DEFAULT_LIMIT = 100;

	@Override
	public String name() {
		return "xrefs";
	}

	@Override
	public String description() {
		return "List cross-references to and/or from a location (address, symbol name, or " +
			"function). direction defaults to 'to'. Paginated with offset/limit.";
	}

	@Override
	public Map<String, Object> inputSchema() {
		return Map.of(
			"type", "object",
			"properties", Map.of(
				"target", Results.stringProp("Address, symbol name, or function name"),
				"direction", Results.enumProp("Which references to show (default 'to')", DIRECTIONS),
				"offset", Results.intProp("Skip this many (default 0)"),
				"limit", Results.intProp("Maximum to return (default " + DEFAULT_LIMIT + ")")),
			"required", List.of("target"));
	}

	@Override
	public boolean isReadOnly() {
		return true;
	}

	@Override
	public McpSchema.CallToolResult execute(Map<String, Object> args, Program program) {
		String target = Results.stringArg(args, "target", null);
		if (target == null) {
			return Results.error("target is required");
		}
		String direction = Results.stringArg(args, "direction", "to");
		if (!DIRECTIONS.contains(direction)) {
			return Results.error("direction must be one of " + DIRECTIONS);
		}
		int offset = Math.max(0, Results.intArg(args, "offset", 0));
		int limit = Math.max(1, Results.intArg(args, "limit", DEFAULT_LIMIT));

		Address address = ProgramContext.findLocation(program, target);
		ReferenceManager refs = program.getReferenceManager();

		List<String> all = new ArrayList<>();
		if (direction.equals("to") || direction.equals("both")) {
			ReferenceIterator it = refs.getReferencesTo(address);
			while (it.hasNext()) {
				all.add(describe(program, "TO  ", it.next(), true));
			}
		}
		if (direction.equals("from") || direction.equals("both")) {
			for (Reference ref : refs.getReferencesFrom(address)) {
				all.add(describe(program, "FROM", ref, false));
			}
		}

		if (all.isEmpty()) {
			return Results.ok("No " + direction + " references for " + target + " (" + address + ")");
		}
		List<String> window = all.stream().skip(offset).limit(limit).toList();
		return Results.ok(String.join("\n", window) + "\n" +
			Results.paginationFooter(window.size(), offset, all.size()));
	}

	private static String describe(Program program, String tag, Reference ref, boolean useFrom) {
		Address address = useFrom ? ref.getFromAddress() : ref.getToAddress();
		Function containing = program.getFunctionManager().getFunctionContaining(address);
		String context = containing != null
				? "  in " + containing.getName() + "+" +
					(address.subtract(containing.getEntryPoint()))
				: "";
		return tag + "  " + address + "  [" + ref.getReferenceType() + "]" + context;
	}
}
