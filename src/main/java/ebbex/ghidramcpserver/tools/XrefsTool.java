package ebbex.ghidramcpserver.tools;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import ebbex.ghidramcpserver.ProgramTool;
import ebbex.ghidramcpserver.util.Args;
import ebbex.ghidramcpserver.util.Locations;
import ebbex.ghidramcpserver.util.Results;
import ebbex.ghidramcpserver.util.Schemas;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.ReferenceManager;
import io.modelcontextprotocol.spec.McpSchema;

/**
 * Cross-references to and/or from a point (a single address or symbol) or a range (a whole
 * function body, or an explicit address range). The range form is what makes "which references
 * come <em>from</em> this segment?" askable: references live on the instruction that makes them,
 * not on the entry point of the function containing it, so a point query on a function name only
 * ever sees the entry address.
 */
public class XrefsTool implements ProgramTool {

	private static final List<String> DIRECTIONS = List.of("to", "from", "both");
	private static final int DEFAULT_LIMIT = 100;

	@Override
	public String name() {
		return "xrefs";
	}

	@Override
	public String description() {
		return "List cross-references to and/or from a point or a range. Give exactly one target: " +
			"'location' (a single address or symbol name), 'function' (its whole body — references " +
			"are recorded on the instruction that makes them, so a function's 'from' references are " +
			"NOT all at its entry address), or 'min_address'/'max_address' (an explicit range, e.g. " +
			"a whole segment). direction defaults to 'to'. 'filter' keeps only lines containing the " +
			"given text, which is how you constrain the other endpoint (e.g. filter='2b5a:' for refs " +
			"landing in that segment). Paginated with offset/limit.";
	}

	@Override
	public Map<String, Object> inputSchema() {
		Map<String, Object> properties = new LinkedHashMap<>();
		properties.put("location", Schemas.stringProp("A single address or symbol name"));
		properties.put("function",
			Schemas.stringProp("Function name or an address inside it; queries its whole body"));
		properties.put("min_address", Schemas.stringProp("Range start (inclusive)"));
		properties.put("max_address", Schemas.stringProp("Range end (inclusive)"));
		properties.put("direction",
			Schemas.enumProp("Which references to show (default 'to')", DIRECTIONS));
		properties.put("filter",
			Schemas.stringProp("Keep only lines containing this text (case-insensitive)"));
		properties.put("offset", Schemas.intProp("Skip this many (default 0)"));
		properties.put("limit", Schemas.intProp("Maximum to return (default " + DEFAULT_LIMIT + ")"));
		return Map.of("type", "object", "properties", properties);
	}

	@Override
	public boolean isReadOnly() {
		return true;
	}

	@Override
	public McpSchema.CallToolResult execute(Map<String, Object> args, Program program) {
		String location = Args.stringArg(args, "location", null);
		String functionRef = Args.stringArg(args, "function", null);
		String minArg = Args.stringArg(args, "min_address", null);
		String maxArg = Args.stringArg(args, "max_address", null);

		int targets = (location != null ? 1 : 0) + (functionRef != null ? 1 : 0) +
			(minArg != null || maxArg != null ? 1 : 0);
		if (targets == 0) {
			return Results.error("give exactly one target: 'location' (address or symbol), " +
				"'function' (whole body), or 'min_address'/'max_address' (a range)");
		}
		if (targets > 1) {
			return Results.error("'location', 'function' and 'min_address'/'max_address' are " +
				"alternative targets — give exactly one");
		}

		String direction = Args.stringArg(args, "direction", "to");
		if (!DIRECTIONS.contains(direction)) {
			return Results.error("direction must be one of " + DIRECTIONS);
		}
		String filter = Args.stringArg(args, "filter", null);
		int offset = Math.max(0, Args.intArg(args, "offset", 0));
		int limit = Math.max(1, Args.intArg(args, "limit", DEFAULT_LIMIT));

		List<String> all;
		String what;
		if (location != null) {
			Address address = Locations.findLocation(program, location);
			what = location + " (" + address + ")";
			all = pointRefs(program, address, direction);
		}
		else {
			AddressSetView set;
			if (functionRef != null) {
				Function function = Locations.findFunction(program, functionRef);
				set = function.getBody();
				what = function.getName() + " body (" + set.getMinAddress() + " - " +
					set.getMaxAddress() + ", " + set.getNumAddresses() + " bytes)";
			}
			else {
				if (minArg == null || maxArg == null) {
					return Results.error("a range needs both 'min_address' and 'max_address'");
				}
				Address min = Locations.parseAddress(program, minArg);
				Address max = Locations.parseAddress(program, maxArg);
				// A range spanning two spaces is meaningless and AddressSet throws on it — say so
				// in the tool's own terms, since one overlay/segment per query is the normal shape.
				if (!min.getAddressSpace().equals(max.getAddressSpace())) {
					return Results.error("min_address (" + min + ") and max_address (" + max +
						") are in different address spaces — query one segment/overlay at a time");
				}
				if (min.compareTo(max) > 0) {
					return Results.error("min_address (" + min + ") is after max_address (" + max + ")");
				}
				set = new AddressSet(min, max);
				what = min + " - " + max;
			}
			all = rangeRefs(program, set, direction);
		}

		int unfiltered = all.size();
		if (filter != null && !filter.isBlank()) {
			String needle = filter.toLowerCase(Locale.ROOT);
			all = all.stream().filter(l -> l.toLowerCase(Locale.ROOT).contains(needle)).toList();
		}

		if (all.isEmpty()) {
			String none = "No " + direction + " references for " + what +
				(unfiltered > 0 ? " matching filter '" + filter + "' (" + unfiltered +
					" before filtering)" : "");
			// The "who references this?" direction is the one where a bare zero is ambiguous:
			// Ghidra doesn't materialize references for unresolved computed/indirect accesses,
			// so zero direct refs is not proof the target is unused.
			if (unfiltered == 0 && (direction.equals("to") || direction.equals("both"))) {
				return Results.ok(none + ".\nNote: Ghidra does not track unresolved computed/" +
					"indirect references (jump tables, far calls, register-relative data). Zero " +
					"direct refs is NOT proof the target is unused — confirm by searching the raw " +
					"call/pointer encoding with search_memory kind=bytes.");
			}
			return Results.ok(none);
		}
		List<String> window = all.stream().skip(offset).limit(limit).toList();
		return Results.ok(String.join("\n", window) + (window.isEmpty() ? "" : "\n") +
			Results.paginationFooter(window.size(), offset, all.size()));
	}

	/** References at one address: the queried endpoint is implied, so only the other is shown. */
	private static List<String> pointRefs(Program program, Address address, String direction) {
		ReferenceManager refs = program.getReferenceManager();
		List<String> all = new ArrayList<>();
		if (!direction.equals("from")) {
			ReferenceIterator it = refs.getReferencesTo(address);
			while (it.hasNext()) {
				Reference ref = it.next();
				all.add("TO    " + endpoint(program, ref.getFromAddress()) + type(ref));
			}
		}
		if (!direction.equals("to")) {
			for (Reference ref : refs.getReferencesFrom(address)) {
				all.add("FROM  " + endpoint(program, ref.getToAddress()) + type(ref));
			}
		}
		return all;
	}

	/**
	 * References over an address set. Both endpoints are named — in a range query neither is
	 * implied, and the caller needs the exact (from, to) pair to act on the result (e.g. to
	 * feed clear kind=reference through batch).
	 */
	private static List<String> rangeRefs(Program program, AddressSetView set, String direction) {
		ReferenceManager refs = program.getReferenceManager();
		List<String> all = new ArrayList<>();
		if (!direction.equals("to")) {
			AddressIterator sources = refs.getReferenceSourceIterator(set, true);
			for (Address from : sources) {
				for (Reference ref : refs.getReferencesFrom(from)) {
					all.add("FROM  " + pair(program, ref));
				}
			}
		}
		if (!direction.equals("from")) {
			AddressIterator destinations = refs.getReferenceDestinationIterator(set, true);
			for (Address to : destinations) {
				ReferenceIterator it = refs.getReferencesTo(to);
				while (it.hasNext()) {
					all.add("TO    " + pair(program, it.next()));
				}
			}
		}
		return all;
	}

	private static String pair(Program program, Reference ref) {
		return endpoint(program, ref.getFromAddress()) + "  ->  " +
			endpoint(program, ref.getToAddress()) + type(ref);
	}

	/** An address plus the function it lands in, if any. */
	private static String endpoint(Program program, Address address) {
		return address + containing(program, address);
	}

	private static String containing(Program program, Address address) {
		Function function = program.getFunctionManager().getFunctionContaining(address);
		if (function == null) {
			return "";
		}
		long offset = address.subtract(function.getEntryPoint());
		return "  in " + function.getName() + "+" + offset;
	}

	private static String type(Reference ref) {
		RefType refType = ref.getReferenceType();
		String nature = refType.isComputed() ? " computed" : refType.isIndirect() ? " indirect" : "";
		return "  [" + refType + nature + "]";
	}
}
