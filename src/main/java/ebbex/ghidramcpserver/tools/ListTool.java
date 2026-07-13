package ebbex.ghidramcpserver.tools;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import ebbex.ghidramcpserver.ProgramTool;
import ebbex.ghidramcpserver.util.Args;
import ebbex.ghidramcpserver.util.Locations;
import ebbex.ghidramcpserver.util.Results;
import ebbex.ghidramcpserver.util.Schemas;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.StringDataInstance;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolType;
import ghidra.program.util.DefinedDataIterator;
import io.modelcontextprotocol.spec.McpSchema;

/**
 * One consolidated enumeration tool: functions, symbols, strings, imports,
 * exports, segments, data, and namespaces, with filtering and pagination.
 */
public class ListTool implements ProgramTool {

	private static final List<String> KINDS = List.of("functions", "symbols", "strings",
		"imports", "exports", "segments", "data", "namespaces", "bookmarks");

	private static final List<String> SORTS = List.of("address", "name", "callers");

	/** Kinds whose items carry a symbol, so 'is this name auto-generated?' is answerable. */
	private static final List<String> USER_ONLY_KINDS = List.of("functions", "symbols", "data");

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
			"descending — the quickest way to spot heavily-used leaf helpers like memcpy/strlen). " +
			"user_only=true (kind=functions|symbols|data) keeps only names a human or analyzer " +
			"gave, dropping Ghidra's auto-generated ones (FUN_*, LAB_*, DAT_*, …) — the way to " +
			"export the curated symbol map without a script. kind=functions also shows each " +
			"function's body size and takes min_body/max_body (bytes): max_body=1 enumerates " +
			"'husk' functions whose code was never disassembled. kind=bookmarks lists bookmarks " +
			"(type/category/address/comment) — this is where the disassembler records its own " +
			"failures as ERROR 'Bad Instruction' marks, so filter=error to see what it could not " +
			"decode.";
	}

	@Override
	public Map<String, Object> inputSchema() {
		return Map.of(
			"type", "object",
			"properties", Map.of(
				"kind", Schemas.enumProp("What to list", KINDS),
				"filter", Schemas.stringProp(
					"Case-insensitive substring to match against names/values"),
				"sort", Schemas.enumProp("Sort order for kind=functions (default address)", SORTS),
				"min_address", Schemas.stringProp(
					"kind=functions: only functions with entry >= this address"),
				"max_address", Schemas.stringProp(
					"kind=functions: only functions with entry <= this address"),
				"user_only", Schemas.boolProp("kind=functions|symbols|data: keep only " +
					"non-auto-generated names (default false)"),
				"min_body", Schemas.intProp("kind=functions: only functions whose body is at " +
					"least this many bytes"),
				"max_body", Schemas.intProp("kind=functions: only functions whose body is at most " +
					"this many bytes (max_body=1 finds husks — a function object over undefined " +
					"bytes, holding no code)"),
				"offset", Schemas.intProp("Skip this many matches (default 0)"),
				"limit", Schemas.intProp("Maximum matches to return (default " +
					DEFAULT_LIMIT + ")")),
			"required", List.of("kind"));
	}

	@Override
	public boolean isReadOnly() {
		return true;
	}

	@Override
	public McpSchema.CallToolResult execute(Map<String, Object> args, Program program) {
		String kind = Args.stringArg(args, "kind", null);
		if (kind == null || !KINDS.contains(kind)) {
			return Results.error("kind must be one of " + KINDS);
		}
		String sort = Args.stringArg(args, "sort", "address");
		if (!SORTS.contains(sort)) {
			return Results.error("sort must be one of " + SORTS);
		}
		String filter = Args.stringArg(args, "filter", "").toLowerCase();
		boolean userOnly = Args.boolArg(args, "user_only", false);
		int offset = Math.max(0, Args.intArg(args, "offset", 0));
		int limit = Math.max(1, Args.intArg(args, "limit", DEFAULT_LIMIT));

		Address from = null;
		Address to = null;
		try {
			String minArg = Args.stringArg(args, "min_address", null);
			String maxArg = Args.stringArg(args, "max_address", null);
			if (minArg != null) {
				from = Locations.parseAddress(program, minArg);
			}
			if (maxArg != null) {
				to = Locations.parseAddress(program, maxArg);
			}
		}
		catch (IllegalArgumentException e) {
			return Results.error(e.getMessage());
		}

		if (userOnly && !USER_ONLY_KINDS.contains(kind)) {
			return Results.error("user_only applies to kind=" + String.join("|", USER_ONLY_KINDS));
		}

		long minBody = Args.intArg(args, "min_body", -1);
		long maxBody = Args.intArg(args, "max_body", -1);
		if ((minBody >= 0 || maxBody >= 0) && !kind.equals("functions")) {
			return Results.error("min_body/max_body apply to kind=functions");
		}

		Iterator<String> lines =
			lines(kind, program, sort, from, to, userOnly, minBody, maxBody);

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
		if (total == 0) {
			return Results.ok("No " + kind + (filter.isEmpty() ? "" : " matching '" + filter + "'") +
				skipNote);
		}
		return Results.ok(String.join("\n", window) + (window.isEmpty() ? "" : "\n") +
			Results.paginationFooter(window.size(), offset, total) + skipNote);
	}

	private Iterator<String> lines(String kind, Program program, String sort, Address from,
			Address to, boolean userOnly, long minBody, long maxBody) {
		return switch (kind) {
			case "functions" -> functionLines(program, sort, from, to, userOnly, minBody, maxBody)
					.iterator();
			case "bookmarks" -> bookmarks(program);
			case "symbols" -> map(filter(program.getSymbolTable().getAllSymbols(true),
				s -> !userOnly || isUserNamed(s)),
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
			case "data" -> map(filter(program.getListing().getDefinedData(true).iterator(),
				d -> !userOnly || isUserNamedData(program, d)), ListTool::dataLine);
			case "namespaces" -> namespaces(program);
			default -> throw new IllegalArgumentException(kind);
		};
	}

	/** Function lines carry a caller count and body size; sortable by address, name, or callers. */
	private List<String> functionLines(Program program, String sort, Address from, Address to,
			boolean userOnly, long minBody, long maxBody) {
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
			if (userOnly && !isUserNamed(f.getSymbol())) {
				continue;
			}
			long body = f.getBody().getNumAddresses();
			if (minBody >= 0 && body < minBody) {
				continue;
			}
			if (maxBody >= 0 && body > maxBody) {
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

		Listing listing = program.getListing();
		List<String> lines = new ArrayList<>(functions.size());
		for (Function f : functions) {
			int callers = refs.getReferenceCountTo(f.getEntryPoint());
			long body = f.getBody().getNumAddresses();
			// A function object whose entry holds no instruction has no code at all — it looks
			// resolved to every consumer while being empty. Say so on the line itself.
			boolean husk = !f.isThunk() && listing.getInstructionAt(f.getEntryPoint()) == null;
			lines.add(f.getEntryPoint() + "  [" + callers + " callers, " + body + "B]  " +
				signatureOf(f) + (husk ? "  <-- HUSK: no code at entry" : ""));
		}
		return lines;
	}

	/**
	 * Bookmarks, including the ERROR marks the disassembler leaves where it gave up ("Bad
	 * Instruction"). Those are the program's own record of what it could not decode, and nothing
	 * else in the tool set surfaces them — {@code filter=error} is the fast way to ask a fresh
	 * import what went wrong.
	 */
	private static Iterator<String> bookmarks(Program program) {
		return map(program.getBookmarkManager().getBookmarksIterator(),
			b -> b.getAddress() + "  [" + b.getTypeString() +
				(b.getCategory().isEmpty() ? "" : "/" + b.getCategory()) + "]  " + b.getComment());
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

	/**
	 * True when the symbol's name came from a human, an importer, or an analyzer rather than
	 * Ghidra's placeholder naming. {@link SourceType#DEFAULT} covers exactly the auto-generated
	 * forms ({@code FUN_*}, {@code LAB_*}, {@code DAT_*}, …), which are noise in a curated
	 * symbol map — and, unlike matching name prefixes, it also keeps analyzer-assigned names
	 * such as the RTLink {@code OVLxx_*} stubs classifiable by their source rather than by
	 * how they happen to be spelled.
	 */
	private static boolean isUserNamed(Symbol symbol) {
		return symbol != null && !symbol.isDynamic() && symbol.getSource() != SourceType.DEFAULT;
	}

	/** Defined data counts as user-named when a non-default symbol sits at its address. */
	private static boolean isUserNamedData(Program program, Data data) {
		return isUserNamed(program.getSymbolTable().getPrimarySymbol(data.getAddress()));
	}

	private static <T> Iterator<T> filter(Iterator<T> it, java.util.function.Predicate<T> keep) {
		return new Iterator<>() {
			private T next;

			@Override
			public boolean hasNext() {
				while (next == null && it.hasNext()) {
					T candidate = it.next();
					if (keep.test(candidate)) {
						next = candidate;
					}
				}
				return next != null;
			}

			@Override
			public T next() {
				if (!hasNext()) {
					throw new java.util.NoSuchElementException();
				}
				T result = next;
				next = null;
				return result;
			}
		};
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
