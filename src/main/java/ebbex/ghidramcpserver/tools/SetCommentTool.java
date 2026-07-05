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
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import io.modelcontextprotocol.spec.McpSchema;

/** Set or clear any comment type at an address (or on a function's entry). */
public class SetCommentTool implements ProgramTool {

	private static final List<String> TYPES = List.of("eol", "pre", "post", "plate", "repeatable");

	@Override
	public String name() {
		return "set_comment";
	}

	@Override
	public String description() {
		return "Set a comment at an address (or on a function's entry point). comment_type is " +
			"one of eol, pre, post, plate, repeatable (default eol). Pass an empty 'comment' to " +
			"clear it.";
	}

	@Override
	public Map<String, Object> inputSchema() {
		return Map.of(
			"type", "object",
			"properties", Map.of(
				"address", Schemas.stringProp("Address to comment (or omit and pass 'function')"),
				"function", Schemas.stringProp("Function name/address; comments its entry point"),
				"comment_type", Schemas.enumProp("Which comment slot (default eol)", TYPES),
				"comment", Schemas.stringProp("Comment text; empty string clears it")),
			"required", List.of("comment"));
	}

	@Override
	public boolean isReadOnly() {
		return false;
	}

	@Override
	public McpSchema.CallToolResult execute(Map<String, Object> args, Program program) {
		String comment = Args.stringArg(args, "comment", null);
		if (comment == null) {
			return Results.error("comment is required (use empty string to clear)");
		}
		CommentType type = parseType(Args.stringArg(args, "comment_type", "eol"));
		if (type == null) {
			return Results.error("comment_type must be one of " + TYPES);
		}

		Address address;
		String addressArg = Args.stringArg(args, "address", null);
		String functionArg = Args.stringArg(args, "function", null);
		if (addressArg != null) {
			address = Locations.parseAddress(program, addressArg);
		}
		else if (functionArg != null) {
			Function function = Locations.findFunction(program, functionArg);
			address = function.getEntryPoint();
		}
		else {
			return Results.error("Provide either 'address' or 'function'");
		}

		return Transactions.modify(program, "Set comment", () -> {
			program.getListing().setComment(address, type, comment.isEmpty() ? null : comment);
			return (comment.isEmpty() ? "Cleared " : "Set ") + type + " comment @ " + address;
		});
	}

	private static CommentType parseType(String s) {
		return switch (s.toLowerCase()) {
			case "eol" -> CommentType.EOL;
			case "pre" -> CommentType.PRE;
			case "post" -> CommentType.POST;
			case "plate" -> CommentType.PLATE;
			case "repeatable" -> CommentType.REPEATABLE;
			default -> null;
		};
	}
}
