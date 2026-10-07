package ebbex.ghidramcpserver.tools;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import ebbex.ghidramcpserver.ProgramTool;
import ebbex.ghidramcpserver.util.Decompilers;
import ebbex.ghidramcpserver.util.Args;
import ebbex.ghidramcpserver.util.Locations;
import ebbex.ghidramcpserver.util.Results;
import ebbex.ghidramcpserver.util.Schemas;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.StringDataInstance;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
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
		"imports", "exports", "segments", "data", "namespaces", "bookmarks", "comments",
		"undeclared_inputs");

	/** Longest comment text shown on a listing line; inspect the address for the full text. */
	private static final int MAX_COMMENT_CHARS = 300;

	/** Concurrent decompiles for the undeclared_inputs sweep (the pool backpressures anyway). */
	private static final int SWEEP_THREADS = 8;

	private static final int SWEEP_TIMEOUT_SECONDS = 30;

	private final Decompilers decompilers;

	public ListTool(Decompilers decompilers) {
		this.decompilers = decompilers;
	}

	private static final List<String> SORTS = List.of("address", "name", "callers");

	/** Kinds whose items carry a symbol, so 'is this name auto-generated?' is answerable. */
	/** Bodies smaller than this are never tagged TEXT: short code is printable by chance. */
	private static final long TEXT_BODY_MIN_BYTES = 16;
	/** How much of a body the TEXT check reads. */
	private static final int TEXT_BODY_SAMPLE = 4096;
	private static final double TEXT_BODY_RATIO = 0.85;

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
			"(kind=strings lists only data already DEFINED as a string — text the analyzer never " +
			"typed is found with search_memory kind=text instead) " +
			"paginated with offset/limit (default limit " + DEFAULT_LIMIT + "). For kind=functions " +
			"each line shows a caller count and you can sort by address|name|callers (callers is " +
			"descending — the quickest way to spot heavily-used leaf helpers like memcpy/strlen). " +
			"user_only=true (kind=functions|symbols|data) keeps only names a human or analyzer " +
			"gave, dropping Ghidra's auto-generated ones (FUN_*, LAB_*, DAT_*, …) — the way to " +
			"export the curated symbol map without a script. kind=functions also shows each " +
			"function's body size and takes min_body/max_body (bytes): max_body=1 enumerates " +
			"'husk' functions whose code was never disassembled, and a line ending '<-- TEXT: N% …' " +
			"marks a body that is mostly character data — a string table auto-analysis turned " +
			"into a bogus function (filter='TEXT:' lists them). kind=bookmarks lists bookmarks " +
			"(type/category/address/comment) — this is where the disassembler records its own " +
			"failures as ERROR 'Bad Instruction' marks, so filter=error to see what it could not " +
			"decode. kind=comments lists every plate/pre/eol/post/repeatable comment as 'address  " +
			"[kind]  text' (newlines escaped, text truncated at " + MAX_COMMENT_CHARS + " chars — " +
			"pass full=true to skip truncation when you are about to rewrite the texts); the " +
			"filter matches the whole line, so it can " +
			"find comment text, a comment kind, or an address/overlay prefix, and " +
			"min_address/max_address scope the walk — the way to find every comment containing a " +
			"word without decompiling anything. kind=undeclared_inputs decompiles every function " +
			"in scope (minutes on thousands of functions — scope with min_address/max_address) " +
			"and lists those whose decompilation reads inputs the prototype omits (in_<REG>): " +
			"'address  name  [guessed|committed]  in_AX (AX:2), ...' — the hand-written " +
			"register-argument helpers that otherwise surface one decompile at a time. Registers " +
			"are listed ALPHABETICALLY — the order carries no information about argument " +
			"position. Flag-bit reads (in_CF, in_ZF, ...) are INT/flag-boundary artifacts, not " +
			"arguments: they print separated ('flag bits CF, ZF (not arguments)'), and a " +
			"flags-only function stays listed but tagged as such (filter='flag bits only' " +
			"buckets them); " +
			"filter=guessed or filter=committed narrows to prototypes that need writing vs. " +
			"committed ones that are provably incomplete. CAVEAT: a function mis-declared as " +
			"returning void can sweep CLEAN — its body is dead code, and the in_* reads are " +
			"eliminated with it — so a clean sweep does not prove prototypes complete; " +
			"suspiciously empty decompilations still need a look.";
	}

	@Override
	public Map<String, Object> inputSchema() {
		// LinkedHashMap rather than Map.of: eleven properties (Map.of caps at ten pairs),
		// and a stable declaration order in the schema besides.
		Map<String, Object> properties = new LinkedHashMap<>();
		properties.put("kind", Schemas.enumProp("What to list", KINDS));
		properties.put("filter", Schemas.stringProp(
			"Case-insensitive substring to match against names/values"));
		properties.put("sort",
			Schemas.enumProp("Sort order for kind=functions (default address)", SORTS));
		properties.put("min_address", Schemas.stringProp(
			"kind=functions|comments|undeclared_inputs: only entries at addresses >= this"));
		properties.put("max_address", Schemas.stringProp(
			"kind=functions|comments|undeclared_inputs: only entries at addresses <= this"));
		properties.put("user_only", Schemas.boolProp("kind=functions|symbols|data: keep only " +
			"non-auto-generated names (default false)"));
		properties.put("full", Schemas.boolProp("kind=comments: return full comment texts " +
			"instead of truncating at " + MAX_COMMENT_CHARS + " chars (default false)"));
		properties.put("min_body", Schemas.intProp("kind=functions: only functions whose body " +
			"is at least this many bytes"));
		properties.put("max_body", Schemas.intProp("kind=functions: only functions whose body " +
			"is at most this many bytes (max_body=1 finds husks — a function object over " +
			"undefined bytes, holding no code)"));
		properties.put("offset", Schemas.intProp("Skip this many matches (default 0)"));
		properties.put("limit", Schemas.intProp("Maximum matches to return (default " +
			DEFAULT_LIMIT + ")"));
		return Map.of(
			"type", "object",
			"properties", properties,
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
		boolean full = Args.boolArg(args, "full", false);
		if (full && !kind.equals("comments")) {
			return Results.error("full applies to kind=comments");
		}
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
			lines(kind, program, sort, from, to, userOnly, full, minBody, maxBody);

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
				(kind.equals("strings")
						? " among the DEFINED strings (kind=strings only lists data typed as a " +
							"string; search_memory kind=text scans every byte)"
						: "") +
				skipNote);
		}
		return Results.ok(String.join("\n", window) + (window.isEmpty() ? "" : "\n") +
			Results.paginationFooter(window.size(), offset, total) + skipNote);
	}

	private Iterator<String> lines(String kind, Program program, String sort, Address from,
			Address to, boolean userOnly, boolean full, long minBody, long maxBody) {
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
			case "comments" -> comments(program, from, to, full);
			case "undeclared_inputs" -> undeclaredInputs(program, from, to);
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
			String tag = husk ? "  <-- HUSK: no code at entry" : textBodyTag(program, f);
			lines.add(f.getEntryPoint() + "  [" + callers + " callers, " + body + "B]  " +
				signatureOf(f) + tag);
		}
		return lines;
	}

	/**
	 * "  <-- TEXT: …" when a function's body is mostly character data — auto-analysis happily
	 * disassembles a NUL-separated string table and makes functions of it, and those then read
	 * as real handlers. Printable ASCII plus the NUL/tab/newline that separate strings must
	 * make up {@link #TEXT_BODY_RATIO} of the sampled body; tiny bodies are skipped, since a
	 * handful of instruction bytes can be printable by chance.
	 */
	private static String textBodyTag(Program program, Function f) {
		if (f.isThunk()) {
			return "";
		}
		long size = f.getBody().getNumAddresses();
		if (size < TEXT_BODY_MIN_BYTES) {
			return "";
		}
		int sampled = 0;
		int texty = 0;
		int printable = 0;
		for (AddressRange range : f.getBody()) {
			int want = (int) Math.min(range.getLength(), TEXT_BODY_SAMPLE - sampled);
			byte[] bytes = new byte[want];
			int got;
			try {
				got = program.getMemory().getBytes(range.getMinAddress(), bytes);
			}
			catch (MemoryAccessException e) {
				continue;
			}
			for (int i = 0; i < got; i++) {
				int b = bytes[i] & 0xff;
				if (b >= 0x20 && b < 0x7f) {
					printable++;
					texty++;
				}
				else if (b == 0 || b == '\t' || b == '\n' || b == '\r') {
					texty++;
				}
			}
			sampled += got;
			if (sampled >= TEXT_BODY_SAMPLE) {
				break;
			}
		}
		// Printable must dominate too, or a zero-filled region would qualify.
		if (sampled == 0 || texty < sampled * TEXT_BODY_RATIO || printable * 2 < sampled) {
			return "";
		}
		return "  <-- TEXT: " + (100 * texty / sampled) + "% of the body is character data " +
			"(likely a string table analysis disassembled, not code)";
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

	/**
	 * Every comment in the program (or the min/max_address range), one line per
	 * (address, comment kind) pair. This is the read path {@code set_comment} never had:
	 * before it, "which comments contain X" meant decompiling every candidate function or
	 * grepping stale on-disk buffer files. The listing walks only addresses that carry a
	 * comment ({@code getCommentAddressIterator}), so it is cheap even on a large program.
	 */
	private static Iterator<String> comments(Program program, Address from, Address to,
			boolean full) {
		Listing listing = program.getListing();
		AddressSetView scope = (from == null && to == null)
				? program.getMemory()
				: new AddressSet(
					from != null ? from : program.getMinAddress(),
					to != null ? to : program.getMaxAddress());
		AddressIterator addresses = listing.getCommentAddressIterator(scope, true);
		ArrayDeque<String> pending = new ArrayDeque<>();
		return new Iterator<>() {
			@Override
			public boolean hasNext() {
				while (pending.isEmpty() && addresses.hasNext()) {
					Address address = addresses.next();
					for (CommentType type : CommentType.values()) {
						String comment = listing.getComment(type, address);
						if (comment != null && !comment.isEmpty()) {
							String text = escape(comment);
							pending.add(address + "  [" + type.name().toLowerCase() + "]  " +
								(full ? text : truncate(text)));
						}
					}
				}
				return !pending.isEmpty();
			}

			@Override
			public String next() {
				if (!hasNext()) {
					throw new java.util.NoSuchElementException();
				}
				return pending.poll();
			}
		};
	}

	/**
	 * Functions whose decompilation reads inputs the prototype omits (irregular
	 * {@code in_<REG>} inputs) — enumerated instead of discovered one decompile at a time.
	 * The check inherently needs the decompiler per function (core has no cheaper oracle),
	 * so the sweep decompiles every non-thunk function in scope, {@value #SWEEP_THREADS}
	 * at a time over the shared pool. A function that fails to decompile is listed with
	 * {@code <decompile failed>} rather than silently passed — a failure cannot prove the
	 * prototype complete.
	 */
	private Iterator<String> undeclaredInputs(Program program, Address from, Address to) {
		List<Function> functions = new ArrayList<>();
		Listing listing = program.getListing();
		for (Function f : program.getFunctionManager().getFunctions(true)) {
			Address entry = f.getEntryPoint();
			if (from != null && entry.compareTo(from) < 0) {
				continue;
			}
			if (to != null && entry.compareTo(to) > 0) {
				continue;
			}
			// Thunks decompile as their target; husks have nothing to decompile.
			if (f.isThunk() || listing.getInstructionAt(entry) == null) {
				continue;
			}
			functions.add(f);
		}

		ExecutorService executor = Executors.newFixedThreadPool(SWEEP_THREADS);
		List<Future<String>> futures = new ArrayList<>(functions.size());
		try {
			for (Function f : functions) {
				futures.add(executor.submit(() -> {
					DecompileResults results =
						decompilers.decompile(program, f, SWEEP_TIMEOUT_SECONDS);
					String state = DecompileTool.prototypeState(f);
					if (results == null || !results.decompileCompleted()) {
						return f.getEntryPoint() + "  " + f.getName() + "  [" + state +
							"]  <decompile failed" +
							(results != null && results.getErrorMessage() != null
									? ": " + results.getErrorMessage().strip() : "") + ">";
					}
					DecompileTool.IrregularInputs inputs = DecompileTool.irregularInputs(results);
					if (inputs.isEmpty()) {
						return null;
					}
					return f.getEntryPoint() + "  " + f.getName() + "  [" + state + "]  " +
						inputs.describe();
				}));
			}
		}
		finally {
			executor.shutdown();
		}

		List<String> lines = new ArrayList<>();
		for (Future<String> future : futures) {
			try {
				String line = future.get();
				if (line != null) {
					lines.add(line);
				}
			}
			catch (Exception e) {
				throw new IllegalStateException("undeclared_inputs sweep failed: " + e, e);
			}
		}
		return lines.iterator();
	}

	private static String truncate(String text) {
		return text.length() <= MAX_COMMENT_CHARS
				? text
				: text.substring(0, MAX_COMMENT_CHARS) + "… [truncated — inspect for full text]";
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
