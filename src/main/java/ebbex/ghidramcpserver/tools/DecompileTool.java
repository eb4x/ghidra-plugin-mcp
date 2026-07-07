package ebbex.ghidramcpserver.tools;

import java.util.List;
import java.util.Map;

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
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.PcodeBlockBasic;
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
			"inside it.";
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
					DEFAULT_TIMEOUT + ")")));
	}

	@Override
	public boolean isReadOnly() {
		return true;
	}

	@Override
	public McpSchema.CallToolResult execute(Map<String, Object> args, Program program) {
		int timeout = Args.intArg(args, "timeout_s", DEFAULT_TIMEOUT);

		Object many = args.get("functions");
		if (many instanceof List<?> list && !list.isEmpty()) {
			StringBuilder sb = new StringBuilder();
			int n = Math.min(list.size(), MAX_BATCH);
			for (int i = 0; i < n; i++) {
				sb.append(decompileOne(program, String.valueOf(list.get(i)), timeout)).append("\n");
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
		return Results.ok(decompileOne(program, functionRef, timeout));
	}

	private String decompileOne(Program program, String ref, int timeout) {
		Function function;
		try {
			function = Locations.findFunction(program, ref);
		}
		catch (Exception e) {
			return "// " + ref + ": " + e.getMessage();
		}
		DecompileResults results = decompilers.decompile(program, function, timeout);
		if (results != null && results.getDecompiledFunction() != null) {
			String c = results.getDecompiledFunction().getC();
			if (c != null && !c.isBlank()) {
				return coverageHeader(program, function, results) + c;
			}
		}
		String message = results == null ? "no result" : results.getErrorMessage();
		return "// Decompilation failed for " + function.getName() + ": " +
			(message == null || message.isBlank() ? "unknown" : message);
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
		boolean lowCoverage = total >= MIN_INSTRS_FOR_WARNING
				&& (double) represented / total < LOW_COVERAGE_FRACTION;
		if (lowCoverage || !results.decompileCompleted()) {
			sb.append("  ⚠ LOW COVERAGE —\n//   likely incomplete (corrupt/unresolved bytes "
				+ "or decompiler bailout); cross-check with disassemble");
		}
		return sb.append('\n').toString();
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
