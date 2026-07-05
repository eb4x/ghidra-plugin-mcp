package ebbex.ghidramcpserver.tools;

import java.util.List;
import java.util.Map;

import ebbex.ghidramcpserver.ProgramTool;
import ebbex.ghidramcpserver.util.Args;
import ebbex.ghidramcpserver.util.Locations;
import ebbex.ghidramcpserver.util.Results;
import ebbex.ghidramcpserver.util.Schemas;
import ebbex.ghidramcpserver.util.Transactions;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import io.modelcontextprotocol.spec.McpSchema;

/**
 * Clear instructions and data in an address range back to undefined bytes — the
 * equivalent of selecting a range and pressing "C" (Clear Code Bytes) in Ghidra.
 * Use before re-disassembling a mis-analyzed region (see create kind=instructions).
 */
public class ClearTool implements ProgramTool {

	@Override
	public String name() {
		return "clear";
	}

	@Override
	public String description() {
		return "Clear code/data back to undefined bytes over a range (like pressing 'C' in " +
			"Ghidra). Give 'address' and either 'length' (bytes) or 'end_address'. Follow with " +
			"create kind=instructions to re-disassemble.";
	}

	@Override
	public Map<String, Object> inputSchema() {
		return Map.of(
			"type", "object",
			"properties", Map.of(
				"address", Schemas.stringProp("Start address"),
				"length", Schemas.intProp("Number of bytes to clear (or give end_address)"),
				"end_address", Schemas.stringProp("Inclusive end address (alternative to length)")),
			"required", List.of("address"));
	}

	@Override
	public boolean isReadOnly() {
		return false;
	}

	@Override
	public McpSchema.CallToolResult execute(Map<String, Object> args, Program program) {
		String addressArg = Args.stringArg(args, "address", null);
		if (addressArg == null) {
			return Results.error("address is required");
		}
		Address start = Locations.parseAddress(program, addressArg);

		Address end;
		String endArg = Args.stringArg(args, "end_address", null);
		if (endArg != null) {
			end = Locations.parseAddress(program, endArg);
		}
		else {
			int length = Args.intArg(args, "length", 0);
			if (length <= 0) {
				return Results.error("provide a positive 'length' or an 'end_address'");
			}
			end = start.add(length - 1);
		}

		return Transactions.modify(program, "Clear code bytes", () -> {
			program.getListing().clearCodeUnits(start, end, false);
			return "Cleared " + start + " - " + end + " to undefined bytes";
		});
	}
}
