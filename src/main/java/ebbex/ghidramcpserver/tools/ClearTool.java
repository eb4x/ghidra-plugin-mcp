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
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.Variable;
import io.modelcontextprotocol.spec.McpSchema;

/**
 * Clear something back out of the program. kind=code (default) clears instructions and
 * data in an address range back to undefined bytes — the equivalent of selecting a range
 * and pressing "C" (Clear Code Bytes) in Ghidra. kind=local_variable deletes a function's
 * local variable (Ghidra's "Delete Variable"), useful for stale dynamic locals that no
 * longer map to anything but still occupy their name in the function.
 */
public class ClearTool implements ProgramTool {

	private static final List<String> KINDS = List.of("code", "local_variable");

	@Override
	public String name() {
		return "clear";
	}

	@Override
	public String description() {
		return "Clear something out of the program. kind=code (default) clears code/data back to " +
			"undefined bytes over a range (like pressing 'C' in Ghidra): give 'address' and either " +
			"'length' (bytes) or 'end_address', then follow with create kind=instructions to " +
			"re-disassemble. kind=local_variable deletes the local variable 'variable_name' from " +
			"'function' (Ghidra's Delete Variable) — for removing stale dynamic locals.";
	}

	@Override
	public Map<String, Object> inputSchema() {
		return Map.of(
			"type", "object",
			"properties", Map.of(
				"kind", Schemas.enumProp("What to clear (default 'code')", KINDS),
				"address", Schemas.stringProp("Start address (for kind=code)"),
				"length", Schemas.intProp("Number of bytes to clear (or give end_address)"),
				"end_address", Schemas.stringProp("Inclusive end address (alternative to length)"),
				"function", Schemas.stringProp(
					"Function name or an address inside it (for kind=local_variable)"),
				"variable_name", Schemas.stringProp("Local variable to delete (for kind=local_variable)")));
	}

	@Override
	public boolean isReadOnly() {
		return false;
	}

	@Override
	public McpSchema.CallToolResult execute(Map<String, Object> args, Program program) {
		String kind = Args.stringArg(args, "kind", "code");
		if (!KINDS.contains(kind)) {
			return Results.error("kind must be one of " + KINDS);
		}
		if (kind.equals("local_variable")) {
			return clearLocalVariable(program, args);
		}
		return clearCode(program, args);
	}

	private McpSchema.CallToolResult clearCode(Program program, Map<String, Object> args) {
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

	private McpSchema.CallToolResult clearLocalVariable(Program program, Map<String, Object> args) {
		String functionRef = Args.stringArg(args, "function", null);
		String variableName = Args.stringArg(args, "variable_name", null);
		if (functionRef == null || variableName == null) {
			return Results.error("'function' and 'variable_name' are required for kind=local_variable");
		}
		Function function = Locations.findFunction(program, functionRef);

		Variable target = null;
		for (Variable local : function.getLocalVariables()) {
			if (local.getName().equals(variableName)) {
				target = local;
				break;
			}
		}
		if (target == null) {
			// A parameter is deleted by changing the signature, not here — say so explicitly.
			for (Parameter parameter : function.getParameters()) {
				if (parameter.getName().equals(variableName)) {
					return Results.error("'" + variableName + "' is a parameter of " +
						function.getName() + " — change parameters with set_function_signature, " +
						"not clear");
				}
			}
			return Results.error("No local variable named '" + variableName + "' in " +
				function.getName());
		}

		Variable toRemove = target;
		return Transactions.modify(program, "Delete local variable", () -> {
			function.removeVariable(toRemove);
			return "Deleted local variable " + variableName + " from " + function.getName();
		});
	}
}
