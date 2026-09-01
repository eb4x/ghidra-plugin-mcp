package ebbex.ghidramcpserver.tools;

import java.io.IOException;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import ebbex.ghidramcpserver.ProgramTool;
import ebbex.ghidramcpserver.util.Args;
import ebbex.ghidramcpserver.util.Decompilers;
import ebbex.ghidramcpserver.util.Locations;
import ebbex.ghidramcpserver.util.Results;
import ebbex.ghidramcpserver.util.Schemas;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.DynamicEntry;
import ghidra.program.model.pcode.ElementId;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.JumpTable;
import ghidra.program.model.pcode.PcodeBlockBasic;
import ghidra.program.model.pcode.PcodeDataTypeManager;
import ghidra.program.model.pcode.SymbolEntry;
import ghidra.program.model.pcode.XmlEncode;
import ghidra.program.model.symbol.IdentityNameTransformer;
import ghidra.program.model.symbol.SourceType;
import io.modelcontextprotocol.spec.McpSchema;

/** Decompile a function to C. */
public class DecompileTool implements ProgramTool {

	private static final int DEFAULT_TIMEOUT = 30;
	private static final int MAX_BATCH = 12;

	/**
	 * Below this fraction of a function's instructions being represented in the
	 * decompiler's p-code, flag the decompile as likely incomplete. Deliberately lenient:
	 * healthy decompiles legitimately drop some instructions to optimization, while the
	 * real failure this guards against (a decompiler bailing on corrupt/unresolved bytes)
	 * covers a tiny fraction (~17% in the case that motivated this).
	 */
	private static final double LOW_COVERAGE_FRACTION = 0.5;

	/** Don't warn on tiny functions, where the coverage ratio is noisy. */
	private static final int MIN_INSTRS_FOR_WARNING = 8;

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
			"inside it. The header says whether the signature you are reading is the program's " +
			"('prototype committed') or the decompiler's own invention ('prototype guessed'), and " +
			"warns about UNDECLARED INPUTS — register or stack arguments the prototype omits, " +
			"rendered as in_<REG> locals. Declared params are never reordered: a guessed " +
			"prototype just omits the register args (where they belong among the declared ones " +
			"is unknown), while a WRONG committed prototype mis-binds declared params to the " +
			"wrong storage — plausible values read from the wrong place. Either way, cross-check " +
			"with disassemble. Sweep a whole program for these with list kind=undeclared_inputs.";
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
					DEFAULT_TIMEOUT + ")"),
				"dump_symbols", Schemas.boolProp("Also append the decompiler's HighSymbol table " +
					"(each local/param's name, storage, and — for dynamic locals — hash and pc " +
					"address); for debugging variable mapping/rename persistence (default false)"),
				"dump_jumptables", Schemas.boolProp("Also append the function's jump tables, both " +
					"the overrides sent to the decompiler (read from the <func>::override::jmp_* " +
					"symbol namespace) and the tables the decompiler came back with, so you can " +
					"see whether an override was consumed (default false)")));
	}

	@Override
	public boolean isReadOnly() {
		return true;
	}

	@Override
	public McpSchema.CallToolResult execute(Map<String, Object> args, Program program) {
		int timeout = Args.intArg(args, "timeout_s", DEFAULT_TIMEOUT);
		boolean dumpSymbols = Args.boolArg(args, "dump_symbols", false);
		boolean dumpJumpTables = Args.boolArg(args, "dump_jumptables", false);

		Object many = args.get("functions");
		if (many instanceof List<?> list && !list.isEmpty()) {
			StringBuilder sb = new StringBuilder();
			int n = Math.min(list.size(), MAX_BATCH);
			for (int i = 0; i < n; i++) {
				sb.append(decompileOne(program, String.valueOf(list.get(i)), timeout, dumpSymbols,
					dumpJumpTables)).append("\n");
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
		return Results.ok(
			decompileOne(program, functionRef, timeout, dumpSymbols, dumpJumpTables));
	}

	private String decompileOne(Program program, String ref, int timeout, boolean dumpSymbols,
			boolean dumpJumpTables) {
		Function function;
		try {
			function = Locations.findFunction(program, ref);
		}
		catch (Exception e) {
			return "// " + ref + ": " + e.getMessage();
		}
		DecompileResults results = decompilers.decompile(program, function, timeout);
		StringBuilder out = new StringBuilder();
		String c = results == null || results.getDecompiledFunction() == null ? null
				: results.getDecompiledFunction().getC();
		if (c != null && !c.isBlank()) {
			out.append(coverageHeader(program, function, results))
					.append(undeclaredInputWarning(function, results))
					.append(c);
			if (dumpSymbols) {
				out.append(symbolDump(results.getHighFunction()));
			}
		}
		else {
			String message = results == null ? "no result" : results.getErrorMessage();
			out.append("// Decompilation failed for ").append(function.getName()).append(": ")
					.append(message == null || message.isBlank() ? "unknown" : message)
					.append('\n');
		}
		// After the failure branch too: a bad override is a common reason the decompiler bails,
		// and that is exactly when you need to see what was sent.
		if (dumpJumpTables) {
			out.append(jumpTableDump(program, function, results));
		}
		return out.toString();
	}

	/**
	 * A compact dump of the decompiler's local/parameter {@link HighSymbol}s — the mapping the
	 * Java side computes and hands the decompiler process. Dynamic locals (no fixed storage)
	 * show their hash and pc address, which is what a rename-persistence bug turns on.
	 */
	private static String symbolDump(HighFunction high) {
		if (high == null) {
			return "\n// -- decompiler symbols: none (no high function) --\n";
		}
		StringBuilder sb = new StringBuilder("\n// -- decompiler symbols --\n");
		Iterator<HighSymbol> symbols = high.getLocalSymbolMap().getSymbols();
		while (symbols.hasNext()) {
			HighSymbol symbol = symbols.next();
			sb.append("// ").append(symbol.getName()).append("  ").append(symbol.getStorage())
					.append("  ").append(symbol.getDataType().getName());
			if (symbol.getFirstWholeMap() instanceof DynamicEntry dynamic) {
				sb.append("  hash=0x").append(Long.toHexString(dynamic.getHash()));
				Address pc = symbol.getPCAddress();
				if (pc != null && pc != Address.NO_ADDRESS) {
					sb.append(" pc=").append(pc);
				}
			}
			sb.append('\n');
		}
		return sb.toString();
	}

	/**
	 * Both sides of the jump-table conversation with the decompiler process, so a
	 * decompiler jump-table override — which Ghidra stores purely as symbols under
	 * {@code <func>::override::jmp_<branchaddr>} — can be debugged in one call instead of by
	 * re-decompiling blind.
	 *
	 * <p>"Sent" reconstructs what the Java side transmits: {@code grabFromFunction} is what
	 * walks the override namespace (via {@code JumpTable.readOverride}), exactly as
	 * {@code DecompileCallback.encodeFunction} does before encoding the {@code <function>}
	 * element. It is printed as the {@code <jumptablelist>} XML that goes over the wire. What
	 * came back is summarised per switch address rather than dumped: a recovered table
	 * repeats one {@code <dest>} per case value, which for a wide switch is scores of
	 * near-identical lines and no more information than the counts.
	 *
	 * @param results may be null, or a failed decompile — a bad override is a common reason the
	 *            decompiler bails, so the sent side still has to be printed
	 */
	private static String jumpTableDump(Program program, Function function,
			DecompileResults results) {
		StringBuilder sb = new StringBuilder("\n// -- jump tables --\n");

		JumpTable[] sent;
		if (HighFunction.findOverrideSpace(function) == null) {
			sent = new JumpTable[0];
			sb.append("// sent: no override namespace on ").append(function.getName())
					.append('\n');
		}
		else {
			HighFunction high = new HighFunction(function, program.getLanguage(),
				program.getCompilerSpec(),
				new PcodeDataTypeManager(program, new IdentityNameTransformer()));
			high.grabFromFunction(0, false, false);
			sent = high.getJumpTables();
			sb.append("// sent (from override namespace):\n").append(encodeTables(sent));
		}

		HighFunction resultHigh = results == null ? null : results.getHighFunction();
		JumpTable[] used = resultHigh == null ? new JumpTable[0] : resultHigh.getJumpTables();
		if (sent.length == 0 && used.length == 0) {
			return sb.append("// used: the decompiler recovered no jump tables\n").toString();
		}

		// Match by switch address only: an override JumpTable keeps its destinations in a
		// BasicOverride with no public accessor and leaves addressTable null, so getCases()
		// would throw. Only getSwitchAddress() and encode() are safe on the sent side.
		//
		// Key on the Address, never on its rendering. The sent side's address comes from the
		// override symbol and prints as its own paragraph (12fd:00de); the returned one is
		// rebuilt by the address factory and prints as the 64KB-page default (1000:30ae). Same
		// flat offset, so they are equal() -- but not as strings, which reports every consumed
		// override as NOT CONSUMED.
		Map<Address, String> usedTables = new LinkedHashMap<>();
		for (JumpTable table : used) {
			usedTables.put(table.getSwitchAddress(), describeCases(table));
		}
		for (JumpTable table : sent) {
			Address address = table.getSwitchAddress();
			String cases = usedTables.remove(address);
			sb.append("// => override at ").append(address).append(cases == null
					? ": NOT CONSUMED"
					: ": CONSUMED (" + cases + ")").append('\n');
		}
		for (Map.Entry<Address, String> entry : usedTables.entrySet()) {
			sb.append("// => table at ").append(entry.getKey())
					.append(": decompiler-discovered (").append(entry.getValue()).append(")\n");
		}
		return sb.toString();
	}

	/** The tables as the {@code <jumptablelist>} element they are encoded into on the wire. */
	private static String encodeTables(JumpTable[] tables) {
		if (tables.length == 0) {
			return "//   (none)\n";
		}
		try {
			XmlEncode encoder = new XmlEncode(true);
			encoder.openElement(ElementId.ELEM_JUMPTABLELIST);
			for (JumpTable table : tables) {
				table.encode(encoder);
			}
			encoder.closeElement(ElementId.ELEM_JUMPTABLELIST);
			return encoder.toString().lines().filter(line -> !line.isBlank())
					.map(line -> "//   " + line + "\n").reduce("", String::concat);
		}
		catch (IOException e) {
			return "//   jump table dump failed: " + e.getMessage() + "\n";
		}
	}

	/**
	 * {@code n cases -> m distinct targets}. Case values usually outnumber targets heavily —
	 * every value that falls through to the default lands on the same address. {@code isEmpty()}
	 * covers the null address table that {@code getCases()} would throw on.
	 */
	private static String describeCases(JumpTable table) {
		if (table.isEmpty()) {
			return "0 cases";
		}
		Address[] cases = table.getCases();
		Set<Address> distinct = new LinkedHashSet<>(List.of(cases));
		return cases.length + " cases -> " + distinct.size() + " distinct targets";
	}

	/**
	 * A one- or two-line comment header stating the function's real size versus how much
	 * of it the decompiler actually represented. It exists so a short, clean-looking
	 * decompile of a large function — e.g. an overlay page whose bytes are corrupted at
	 * relocation-fixup sites, where the decompiler silently bails early — is easy to spot
	 * without cross-referencing {@code disassemble}. Mirrors {@link DisassembleTool}'s
	 * habit of citing the byte count when its output looks suspiciously thin.
	 */
	private static String coverageHeader(Program program, Function function,
			DecompileResults results) {
		long bytes = function.getBody().getNumAddresses();
		int[] cov = instructionCoverage(program, function, results);
		int total = cov[0];
		int represented = cov[1];

		StringBuilder sb = new StringBuilder("// ").append(function.getName())
				.append("  body ").append(bytes).append(" bytes, ").append(total)
				.append(" instrs");
		if (total <= 0) {
			// No disassembled instructions in the body — overlay/RTLink dispatch stub territory.
			return sb.append(" — no disassembled instructions in body "
				+ "(overlay/RTLink dispatch stub?)\n").toString();
		}
		int pct = (int) Math.round(100.0 * represented / total);
		sb.append(", decompiler represented ").append(represented).append(" (").append(pct)
				.append("%)");
		sb.append(", prototype ").append(prototypeState(function));
		boolean lowCoverage = total >= MIN_INSTRS_FOR_WARNING
				&& (double) represented / total < LOW_COVERAGE_FRACTION;
		if (lowCoverage || !results.decompileCompleted()) {
			sb.append("  ⚠ LOW COVERAGE —\n//   likely incomplete (corrupt/unresolved bytes "
				+ "or decompiler bailout); cross-check with disassemble");
		}
		return sb.append('\n').toString();
	}

	/**
	 * {@code guessed} or {@code committed} — whether the signature in the rendering below is the
	 * program's or the decompiler's invention.
	 *
	 * <p>{@code SourceType.DEFAULT} is exactly the discriminator the decompiler itself uses:
	 * {@code FunctionPrototype.grabFromFunction} sets neither {@code outputlock} nor
	 * {@code voidinputlock} for a DEFAULT signature, so the decompiler is free to derive its own
	 * return type and parameter list — and does, silently. Any other source (ANALYSIS, IMPORTED,
	 * USER_DEFINED) locks the listing's prototype, so the rendering is the program's own claim.
	 * Note this is deliberately *not* "DEFAULT or ANALYSIS": an analyzer-applied signature (FID, a
	 * demangler) does lock, and calling it a guess would cry wolf on every library match.
	 *
	 * <p>Thunks need no special case: {@code FunctionDB.getSignatureSource} already delegates to
	 * the thunked function, which is the prototype that governs the rendering.
	 */
	static String prototypeState(Function function) {
		return function.getSignatureSource() == SourceType.DEFAULT ? "guessed" : "committed";
	}

	/**
	 * Names the inputs the decompiler read but could not fit into the prototype, because they are
	 * the difference between a decompilation that is wrong and one that merely looks wrong.
	 *
	 * <p>16-bit real-mode code passes arguments in AX/DX/BX as well as on the stack. When the
	 * prototype doesn't declare them, the decompiler still sees the register being read before it
	 * is written, so it materialises an "irregular input" — rendered {@code in_<REG>}, or
	 * {@code in_<space>_<offset>} for one it can't name (an undeclared *stack* argument). The
	 * motivating case rendered {@code surface_fill_rect} as taking {@code (color, h, desc…)} with
	 * no x/y at all, and read perfectly well.
	 *
	 * <p>The hazard differs by prototype state, and an earlier version of this warning got the
	 * mechanism wrong ("the stack args around them may be mis-ordered"): the decompiler never
	 * reorders declared parameters — each is bound to storage computed from the convention plus
	 * declared types. A GUESSED prototype simply omits the register args (its declared-arg list is
	 * the decompiler's own recovery, so where the omitted ones truly belong is unknown); a WRONG
	 * COMMITTED prototype MIS-BINDS declared params to the wrong storage — plausible values read
	 * from the wrong place (verified on 061_strcpy.obj: a near-pointer prototype bound declared
	 * {@code __src} to the high word of the far {@code __dest}).
	 *
	 * <p>Detected by the {@code in_} name prefix, which is what Ghidra's own
	 * {@code FindPotentialDecompilerProblems} and {@code DecompilerParameterIdCmd} match on; the
	 * prefix is emitted by the decompiler core itself ({@code database.cc}, "Irregular input").
	 * {@code in_FS_OFFSET} is excluded for the same reason that script excludes it — it is an
	 * x86-64 thread-local artefact, not a missed argument.
	 */
	private static String undeclaredInputWarning(Function function, DecompileResults results) {
		String inputs = undeclaredInputs(results);
		if (inputs.isEmpty()) {
			return "";
		}
		// Kept to two lines on purpose. On the program this was built for, 7 of a 12-function
		// sample carried undeclared inputs — it is the normal state of an uncommitted 16-bit
		// function, not an exception — so a longer block would cost more than it teaches on every
		// batch decompile. The reasoning lives in this tool's description, paid for once.
		//
		// The remedy differs: a guessed prototype needs one written, whereas a committed one is
		// incomplete and its author believed they were finished — the more alarming of the two.
		boolean committed = "committed".equals(prototypeState(function));
		return "//   ⚠ UNDECLARED INPUTS: " + inputs + (committed
				? " — the committed prototype omits these (incomplete); a wrong\n" +
					"//     committed prototype mis-binds declared params to the wrong storage " +
					"(never reorders them). Re-derive from disassemble + set_function_signature.\n"
				: " — omitted from the guessed prototype; their true positions among\n" +
					"//     the declared args are unknown. Cross-check disassemble, then pin " +
					"with set_function_signature.\n");
	}

	/**
	 * The decompiler's irregular inputs as {@code "in_AX (AX:2), in_BX (BX:2)"}, or {@code ""}.
	 * Shared with {@code list kind=undeclared_inputs}, which sweeps the whole program for
	 * exactly this so the in_* functions can be enumerated instead of tripped over.
	 */
	static String undeclaredInputs(DecompileResults results) {
		HighFunction high = results.getHighFunction();
		if (high == null) {
			return "";
		}
		StringBuilder inputs = new StringBuilder();
		Iterator<HighSymbol> symbols = high.getLocalSymbolMap().getSymbols();
		while (symbols.hasNext()) {
			HighSymbol symbol = symbols.next();
			String name = symbol.getName();
			if (name == null || !name.startsWith("in_") || name.equals("in_FS_OFFSET")) {
				continue;
			}
			if (!inputs.isEmpty()) {
				inputs.append(", ");
			}
			inputs.append(name).append(" (").append(symbol.getStorage()).append(')');
		}
		return inputs.toString();
	}

	/**
	 * {@code {total, represented}}: how many of the function's instructions the decompiler
	 * actually reached. "Represented" means the instruction's address falls inside one of
	 * the decompiler's basic blocks — the code its control-flow recovery covered. This is
	 * measured against basic-block ranges rather than surviving p-code ops on purpose:
	 * optimization folds away many per-instruction ops even in a perfectly good decompile,
	 * whereas a block range still covers every instruction it reached. So this stays near
	 * the instruction count for healthy functions and collapses only when the decompiler
	 * genuinely bailed early (e.g. on an overlay page corrupted at relocation-fixup sites).
	 *
	 * <p>Instructions are walked from the entry point and stop when we leave the function —
	 * the same anchor {@link DisassembleTool} and {@code SyscallsTool} use, because
	 * iterating {@code getInstructions(function.getBody())} can come back empty in 16-bit
	 * segmented programs.
	 */
	private static int[] instructionCoverage(Program program, Function function,
			DecompileResults results) {
		AddressSet covered = coveredBlocks(results);
		InstructionIterator it =
			program.getListing().getInstructions(function.getEntryPoint(), true);
		int total = 0;
		int represented = 0;
		while (it.hasNext()) {
			Address address = it.next().getAddress();
			if (program.getFunctionManager().getFunctionContaining(address) != function) {
				break;
			}
			total++;
			if (covered.contains(address)) {
				represented++;
			}
		}
		return new int[] { total, represented };
	}

	/**
	 * The machine-address ranges the decompiler's {@link HighFunction} basic blocks cover.
	 * The syntax tree is populated because {@code Decompilers.open} enables it.
	 */
	private static AddressSet coveredBlocks(DecompileResults results) {
		AddressSet covered = new AddressSet();
		HighFunction hf = results.getHighFunction();
		if (hf == null) {
			return covered;
		}
		for (PcodeBlockBasic block : hf.getBasicBlocks()) {
			Address start = block.getStart();
			Address stop = block.getStop();
			if (start == null || stop == null
					|| !start.getAddressSpace().equals(stop.getAddressSpace())
					|| start.compareTo(stop) > 0) {
				continue;
			}
			covered.addRange(start, stop);
		}
		return covered;
	}
}
