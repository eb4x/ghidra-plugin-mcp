package ebbex.ghidramcpserver.tools;

import java.util.Map;

import ebbex.ghidramcpserver.ProgramTool;
import ebbex.ghidramcpserver.util.Args;
import ebbex.ghidramcpserver.util.Locations;
import ebbex.ghidramcpserver.util.Results;
import ebbex.ghidramcpserver.util.Schemas;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CodeUnitFormat;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
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
					"Whole function to disassemble: a name OR an address (alias: 'target')"),
				"target", Schemas.stringProp("Alias for 'function'"),
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
		String functionArg = Args.stringArg(args, "function",
			Args.stringArg(args, "target", null));
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
