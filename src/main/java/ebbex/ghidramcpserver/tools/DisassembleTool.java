package ebbex.ghidramcpserver.tools;

import java.util.Map;

import ebbex.ghidramcpserver.McpToolDef;
import ebbex.ghidramcpserver.util.ProgramContext;
import ebbex.ghidramcpserver.util.Results;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CodeUnitFormat;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Program;
import io.modelcontextprotocol.spec.McpSchema;

/** Disassembly listing for a function, or a run of instructions from an address. */
public class DisassembleTool implements McpToolDef {

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
				"function", Results.stringProp("Function name or an address within the function"),
				"address", Results.stringProp("Start address (used when 'function' is omitted)"),
				"count", Results.intProp("Number of instructions from 'address' (default " +
					DEFAULT_COUNT + ")")));
	}

	@Override
	public boolean isReadOnly() {
		return true;
	}

	@Override
	public McpSchema.CallToolResult execute(Map<String, Object> args, Program program) {
		String functionArg = Results.stringArg(args, "function", null);
		String addressArg = Results.stringArg(args, "address", null);
		CodeUnitFormat format = CodeUnitFormat.DEFAULT;
		StringBuilder sb = new StringBuilder();

		if (functionArg != null) {
			Function function = ProgramContext.findFunction(program, functionArg);
			InstructionIterator it =
				program.getListing().getInstructions(function.getBody(), true);
			sb.append(function.getName()).append(" @ ").append(function.getEntryPoint())
					.append('\n');
			appendInstructions(sb, it, format, Integer.MAX_VALUE);
		}
		else if (addressArg != null) {
			int count = Math.min(MAX_COUNT, Math.max(1, Results.intArg(args, "count", DEFAULT_COUNT)));
			Address start = ProgramContext.parseAddress(program, addressArg);
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
}
