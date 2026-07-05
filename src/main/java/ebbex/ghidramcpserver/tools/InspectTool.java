package ebbex.ghidramcpserver.tools;

import java.util.List;
import java.util.Map;

import ebbex.ghidramcpserver.ProgramTool;
import ebbex.ghidramcpserver.util.Args;
import ebbex.ghidramcpserver.util.Locations;
import ebbex.ghidramcpserver.util.Results;
import ebbex.ghidramcpserver.util.Schemas;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Symbol;
import io.modelcontextprotocol.spec.McpSchema;

/** Everything known at one location: symbols, function, data, comments, xref counts. */
public class InspectTool implements ProgramTool {

	@Override
	public String name() {
		return "inspect";
	}

	@Override
	public String description() {
		return "Describe a single location: its symbols, the function containing it (with " +
			"signature), any defined data and its type/value, all comments, and cross-reference " +
			"counts. Accepts an address or a symbol name.";
	}

	@Override
	public Map<String, Object> inputSchema() {
		return Map.of(
			"type", "object",
			"properties", Map.of(
				"location", Schemas.stringProp("Address or symbol name")),
			"required", List.of("location"));
	}

	@Override
	public boolean isReadOnly() {
		return true;
	}

	@Override
	public McpSchema.CallToolResult execute(Map<String, Object> args, Program program) {
		String location = Args.stringArg(args, "location", null);
		if (location == null) {
			return Results.error("'location' (an address or symbol name) is required");
		}
		Address address = Locations.findLocation(program, location);
		StringBuilder sb = new StringBuilder();
		sb.append("Address: ").append(address).append('\n');

		MemoryBlock block = program.getMemory().getBlock(address);
		if (block != null) {
			sb.append("Block: ").append(block.getName()).append('\n');
		}

		Symbol[] symbols = program.getSymbolTable().getSymbols(address);
		if (symbols.length > 0) {
			sb.append("Symbols:\n");
			for (Symbol symbol : symbols) {
				sb.append("  ").append(symbol.getName(true)).append("  [")
						.append(symbol.getSymbolType()).append(symbol.isPrimary() ? ", primary" : "")
						.append("]\n");
			}
		}

		Function function = program.getFunctionManager().getFunctionContaining(address);
		if (function != null) {
			int callers =
				program.getReferenceManager().getReferenceCountTo(function.getEntryPoint());
			sb.append("Function: ").append(function.getSignature().getPrototypeString())
					.append("\n  entry ").append(function.getEntryPoint()).append(", body ")
					.append(function.getBody().getNumAddresses()).append(" bytes, ")
					.append(callers).append(" callers\n");
		}

		Listing listing = program.getListing();
		Data data = listing.getDefinedDataContaining(address);
		if (data != null) {
			sb.append("Data: ").append(data.getDataType().getName()).append(" @ ")
					.append(data.getAddress()).append(" = ")
					.append(data.getDefaultValueRepresentation()).append('\n');
		}

		appendComment(sb, listing, address, CommentType.PLATE, "plate");
		appendComment(sb, listing, address, CommentType.PRE, "pre");
		appendComment(sb, listing, address, CommentType.EOL, "eol");
		appendComment(sb, listing, address, CommentType.POST, "post");
		appendComment(sb, listing, address, CommentType.REPEATABLE, "repeatable");

		int toCount = program.getReferenceManager().getReferenceCountTo(address);
		int fromCount = program.getReferenceManager().getReferenceCountFrom(address);
		sb.append("Xrefs: ").append(toCount).append(" to, ").append(fromCount).append(" from\n");

		return Results.ok(sb.toString());
	}

	private static void appendComment(StringBuilder sb, Listing listing, Address address,
			CommentType type, String label) {
		String comment = listing.getComment(type, address);
		if (comment != null && !comment.isEmpty()) {
			sb.append("Comment[").append(label).append("]: ").append(comment).append('\n');
		}
	}
}
