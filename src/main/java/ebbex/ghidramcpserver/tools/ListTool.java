package ebbex.ghidramcpserver.tools;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import ebbex.ghidramcpserver.McpToolDef;
import ebbex.ghidramcpserver.util.ProgramContext;
import ebbex.ghidramcpserver.util.Results;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.StringDataInstance;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolType;
import ghidra.program.util.DefinedDataIterator;
import io.modelcontextprotocol.spec.McpSchema;

/**
 * One consolidated enumeration tool: functions, symbols, strings, imports,
 * exports, segments, data, and namespaces, with filtering and pagination.
 */
public class ListTool implements McpToolDef {

	private static final List<String> KINDS = List.of("functions", "symbols", "strings",
		"imports", "exports", "segments", "data", "namespaces");

	private static final List<String> SORTS = List.of("address", "name", "callers");

	private static final int DEFAULT_LIMIT = 100;

	@Override
	public String name() {
		return "list";
	}

	@Override
	public String description() {
		return "List program items of one kind (functions, symbols, strings, imports, exports, " +
			"segments, data, namespaces), optionally filtered by a case-insensitive substring, " +
			"paginated with offset/limit (default limit " + DEFAULT_LIMIT + "). For kind=functions " +
			"each line shows a caller count and you can sort by address|name|callers (callers is " +
			"descending — the quickest way to spot heavily-used leaf helpers like memcpy/strlen).";
	}

	@Override
	public Map<String, Object> inputSchema() {
		return Map.of(
			"type", "object",
			"properties", Map.of(
				"kind", Results.enumProp("What to list", KINDS),
				"filter", Results.stringProp(
					"Case-insensitive substring to match against names/values"),
				"sort", Results.enumProp("Sort order for kind=functions (default address)", SORTS),
				"from", Results.stringProp("kind=functions: only functions with entry >= this address"),
				"to", Results.stringProp("kind=functions: only functions with entry <= this address"),
				"offset", Results.intProp("Skip this many matches (default 0)"),
				"limit", Results.intProp("Maximum matches to return (default " +
					DEFAULT_LIMIT + ")")),
			"required", List.of("kind"));
	}

	@Override
	public boolean isReadOnly() {
		return true;
	}

	@Override
	public McpSchema.CallToolResult execute(Map<String, Object> args, Program program) {
		String kind = Results.stringArg(args, "kind", null);
		if (kind == null || !KINDS.contains(kind)) {
			return Results.error("kind must be one of " + KINDS);
		}
		String sort = Results.stringArg(args, "sort", "address");
		if (!SORTS.contains(sort)) {
			return Results.error("sort must be one of " + SORTS);
		}
		String filter = Results.stringArg(args, "filter", "").toLowerCase();
		int offset = Math.max(0, Results.intArg(args, "offset", 0));
		int limit = Math.max(1, Results.intArg(args, "limit", DEFAULT_LIMIT));

		Address from = null;
		Address to = null;
		try {
			String fromArg = Results.stringArg(args, "from", null);
			String toArg = Results.stringArg(args, "to", null);
			if (fromArg != null) {
				from = ProgramContext.parseAddress(program, fromArg);
			}
			if (toArg != null) {
				to = ProgramContext.parseAddress(program, toArg);
			}
		}
		catch (IllegalArgumentException e) {
			return Results.error(e.getMessage());
		}

		Iterator<String> lines = lines(kind, program, sort, from, to);

		List<String> window = new ArrayList<>();
		int total = 0;
		int skipped = 0;
		while (lines.hasNext()) {
			String line;
			try {
				line = lines.next();
			}
			catch (Exception e) {
				// a single malformed item (e.g. a bad string) must not abort the listing
				skipped++;
				continue;
			}
			if (!filter.isEmpty() && !line.toLowerCase().contains(filter)) {
				continue;
			}
			if (total >= offset && window.size() < limit) {
				window.add(line);
			}
			total++;
		}

		String skipNote = skipped > 0 ? "  (" + skipped + " unreadable entries skipped)" : "";
		if (window.isEmpty()) {
			return Results.ok("No " + kind + (filter.isEmpty() ? "" : " matching '" + filter + "'") +
				(offset > 0 ? " at offset " + offset : "") + " (" + total + " total matches)" +
				skipNote);
		}
		return Results.ok(String.join("\n", window) + "\n" +
			Results.paginationFooter(window.size(), offset, total) + skipNote);
	}

	private Iterator<String> lines(String kind, Program program, String sort, Address from,
			Address to) {
		return switch (kind) {
			case "functions" -> functionLines(program, sort, from, to).iterator();
			case "symbols" -> map(program.getSymbolTable().getAllSymbols(true),
				s -> s.getAddress() + "  " + s.getName(true) + "  [" + s.getSymbolType() + "]");
			case "strings" -> map(
				DefinedDataIterator.byDataInstance(program, StringDataInstance::isString)
						.iterator(),
				ListTool::stringLine);
			case "imports" -> map(program.getSymbolTable().getExternalSymbols(),
				s -> s.getName(true) + parentLibrary(s));
			case "exports" -> map(program.getSymbolTable().getExternalEntryPointIterator(),
				a -> {
					Symbol s = program.getSymbolTable().getPrimarySymbol(a);
					return a + "  " + (s != null ? s.getName() : "?");
				});
			case "segments" -> map(List.of(program.getMemory().getBlocks()).iterator(),
				ListTool::segmentLine);
			case "data" -> map(program.getListing().getDefinedData(true).iterator(),
				ListTool::dataLine);
			case "namespaces" -> namespaces(program);
			default -> throw new IllegalArgumentException(kind);
		};
	}

	/** Function lines carry a caller count and are sortable by address, name, or callers. */
	private List<String> functionLines(Program program, String sort, Address from, Address to) {
		ReferenceManager refs = program.getReferenceManager();
		List<Function> functions = new ArrayList<>();
		for (Function f : program.getFunctionManager().getFunctions(true)) {
			Address entry = f.getEntryPoint();
			if (from != null && entry.compareTo(from) < 0) {
				continue;
			}
			if (to != null && entry.compareTo(to) > 0) {
				continue;
			}
			functions.add(f);
		}

		Comparator<Function> comparator = switch (sort) {
			case "name" -> Comparator.comparing(Function::getName, String.CASE_INSENSITIVE_ORDER);
			case "callers" -> Comparator
					.comparingInt((Function f) -> refs.getReferenceCountTo(f.getEntryPoint()))
					.reversed();
			default -> Comparator.comparing(Function::getEntryPoint);
		};
		functions.sort(comparator);

		List<String> lines = new ArrayList<>(functions.size());
		for (Function f : functions) {
			int callers = refs.getReferenceCountTo(f.getEntryPoint());
			lines.add(f.getEntryPoint() + "  [" + callers + " callers]  " + signatureOf(f));
		}
		return lines;
	}

	private static String signatureOf(Function f) {
		try {
			return f.getSignature().getPrototypeString();
		}
		catch (Exception e) {
			return f.getName();
		}
	}

	private static String stringLine(Data data) {
		String value = StringDataInstance.getStringDataInstance(data).getStringValue();
		if (value == null) {
			value = data.getDefaultValueRepresentation();
		}
		return data.getAddress() + "  " + escape(value);
	}

	private static String segmentLine(MemoryBlock block) {
		return String.format("%s-%s  %-16s %s%s%s %s", block.getStart(), block.getEnd(),
			block.getName(), block.isRead() ? "r" : "-", block.isWrite() ? "w" : "-",
			block.isExecute() ? "x" : "-", block.isInitialized() ? "" : "(uninitialized)");
	}

	private static String dataLine(Data data) {
		String label = data.getLabel() != null ? data.getLabel() + "  " : "";
		return data.getAddress() + "  " + label + data.getDataType().getName() + " = " +
			escape(data.getDefaultValueRepresentation());
	}

	private static String parentLibrary(Symbol s) {
		String parent = s.getParentNamespace().getName();
		return parent.isEmpty() ? "" : "  [" + parent + "]";
	}

	private Iterator<String> namespaces(Program program) {
		List<String> result = new ArrayList<>();
		var it = program.getSymbolTable().getAllSymbols(true);
		while (it.hasNext()) {
			Symbol s = it.next();
			SymbolType type = s.getSymbolType();
			if (type == SymbolType.NAMESPACE || type == SymbolType.CLASS) {
				result.add(s.getName(true) + "  [" + type + "]");
			}
		}
		return result.iterator();
	}

	private static String escape(String value) {
		return value.replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t");
	}

	private static <T> Iterator<String> map(Iterator<T> it, java.util.function.Function<T, String> fn) {
		return new Iterator<>() {
			@Override
			public boolean hasNext() {
				return it.hasNext();
			}

			@Override
			public String next() {
				return fn.apply(it.next());
			}
		};
	}
}
