package ebbex.ghidramcpserver.tools;

import java.util.Map;

import ebbex.ghidramcpserver.ProgramTool;
import ebbex.ghidramcpserver.util.Args;
import ebbex.ghidramcpserver.util.Locations;
import ebbex.ghidramcpserver.util.Results;
import ebbex.ghidramcpserver.util.Schemas;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CodeUnitFormat;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import io.modelcontextprotocol.spec.McpSchema;

/** Disassembly listing for a function, or a run of instructions from an address. */
public class DisassembleTool implements ProgramTool {

	private static final int DEFAULT_COUNT = 32;
	private static final int MAX_COUNT = 4096;

	@Override
	public String name() {
		return "disassemble";
	}

	@Override
	public String description() {
		return "Show disassembly. Give a 'function' (name or contained address) to disassemble a " +
			"whole function, or an 'address' plus 'count' instructions (default " + DEFAULT_COUNT +
			").";
	}

	@Override
	public Map<String, Object> inputSchema() {
		return Map.of(
			"type", "object",
			"properties", Map.of(
				"function", Schemas.stringProp(
					"Whole function to disassemble: a function name or an address inside it"),
				"address", Schemas.stringProp(
					"Start address for a raw run of instructions (when no function is given)"),
				"count", Schemas.intProp("Number of instructions from 'address' (default " +
					DEFAULT_COUNT + ")")));
	}

	@Override
	public boolean isReadOnly() {
		return true;
	}

	@Override
	public McpSchema.CallToolResult execute(Map<String, Object> args, Program program) {
		String functionArg = Args.stringArg(args, "function", null);
		String addressArg = Args.stringArg(args, "address", null);
		CodeUnitFormat format = CodeUnitFormat.DEFAULT;
		StringBuilder sb = new StringBuilder();

		if (functionArg != null) {
			Function function = Locations.findFunction(program, functionArg);
			sb.append(function.getName()).append(" @ ").append(function.getEntryPoint())
					.append('\n');
			int emitted = appendFunctionInstructions(sb, program, function, format);
			if (emitted == 0) {
				sb.append("(no disassembled instructions in the ")
						.append(function.getBody().getNumAddresses())
						.append("-byte body — likely an overlay/RTLink dispatch stub; use " +
							"decompile to see the resolved code)\n");
			}
		}
		else if (addressArg != null) {
			int count = Math.min(MAX_COUNT, Math.max(1, Args.intArg(args, "count", DEFAULT_COUNT)));
			Address start = Locations.parseAddress(program, addressArg);
			// Say so when the requested address holds no code. The iterator silently begins at the
			// next instruction, which reads as "we looked here and found nothing" when in truth
			// those bytes were never examined — that misreading cost a real investigation a day.
			appendUndefinedNote(sb, program, start);
			InstructionIterator it = program.getListing().getInstructions(start, true);
			appendInstructions(sb, it, format, count);
		}
		else {
			return Results.error("Provide either 'function' or 'address'");
		}

		if (sb.length() == 0) {
			return Results.ok("No instructions (address may not be disassembled)");
		}
		return Results.ok(sb.toString());
	}

	/**
	 * Prefix a marker when {@code start} is not the first byte of an instruction, naming what is
	 * actually there and where the listing will therefore resume. Two distinct cases, both of
	 * which the bare listing hides: the address holds <em>undefined bytes</em> (never
	 * disassembled — say how many, up to the next instruction), or it is <em>offcut</em>, i.e.
	 * inside an instruction that starts earlier.
	 */
	private static void appendUndefinedNote(StringBuilder sb, Program program, Address start) {
		Listing listing = program.getListing();
		if (listing.getInstructionAt(start) != null) {
			return;
		}
		Instruction containing = listing.getInstructionContaining(start);
		if (containing != null) {
			sb.append("NOTE: ").append(start).append(" is OFFCUT — inside the instruction at ")
					.append(containing.getAddress()).append("; listing resumes at the next one.\n");
			return;
		}
		Data data = listing.getDefinedDataContaining(start);
		Instruction next = listing.getInstructionAfter(start);
		sb.append("NOTE: ").append(start).append(" holds ")
				.append(data != null ? "defined data (" + data.getDataType().getName() + ")"
						: "UNDEFINED bytes (never disassembled)");
		if (next != null) {
			sb.append("; nothing is disassembled until ").append(next.getAddress());
			try {
				sb.append(" (0x").append(Long.toHexString(next.getAddress().subtract(start)))
						.append(" bytes)");
			}
			catch (Exception spansSpaces) {
				// different address space: the byte distance is meaningless, skip it
			}
		}
		else {
			sb.append("; no further instructions in the program");
		}
		sb.append(".\nThe listing below therefore SKIPS the requested address — it is not evidence " +
			"that those bytes are not code. Use create kind=instructions to disassemble them.\n");
	}

	private void appendInstructions(StringBuilder sb, InstructionIterator it,
			CodeUnitFormat format, int max) {
		int n = 0;
		while (it.hasNext() && n < max) {
			Instruction instruction = it.next();
			sb.append(instruction.getAddress()).append("  ")
					.append(format.getRepresentationString(instruction)).append('\n');
			n++;
		}
	}

	/**
	 * Walk instructions from the entry point, stopping when we leave the function.
	 * (Iterating {@code getInstructions(function.getBody())} can come back empty in
	 * 16-bit segmented programs, so anchor on the entry point instead.)
	 */
	private int appendFunctionInstructions(StringBuilder sb, Program program, Function function,
			CodeUnitFormat format) {
		InstructionIterator it = program.getListing().getInstructions(function.getEntryPoint(), true);
		int emitted = 0;
		while (it.hasNext() && emitted < MAX_COUNT * 4) {
			Instruction instruction = it.next();
			if (program.getFunctionManager()
					.getFunctionContaining(instruction.getAddress()) != function) {
				break;
			}
			sb.append(instruction.getAddress()).append("  ")
					.append(format.getRepresentationString(instruction)).append('\n');
			emitted++;
		}
		return emitted;
	}
}
