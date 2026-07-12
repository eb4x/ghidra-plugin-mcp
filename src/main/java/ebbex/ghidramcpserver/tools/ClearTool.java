package ebbex.ghidramcpserver.tools;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import ebbex.ghidramcpserver.ProgramTool;
import ebbex.ghidramcpserver.util.Args;
import ebbex.ghidramcpserver.util.Locations;
import ebbex.ghidramcpserver.util.Results;
import ebbex.ghidramcpserver.util.Schemas;
import ebbex.ghidramcpserver.util.Transactions;
import ghidra.app.cmd.function.DeleteFunctionCmd;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolType;
import io.modelcontextprotocol.spec.McpSchema;

/**
 * Clear something back out of the program. kind=code (default) clears instructions and
 * data in an address range back to undefined bytes — the equivalent of selecting a range
 * and pressing "C" (Clear Code Bytes) in Ghidra. kind=local_variable deletes a function's
 * local variable (Ghidra's "Delete Variable"), useful for stale dynamic locals that no
 * longer map to anything but still occupy their name in the function.
 */
public class ClearTool implements ProgramTool {

	private static final List<String> KINDS =
		List.of("code", "local_variable", "label", "function", "reference");

	@Override
	public String name() {
		return "clear";
	}

	@Override
	public String description() {
		return "Clear/delete something out of the program. kind=code (default) clears code/data back " +
			"to undefined bytes over a range (like pressing 'C' in Ghidra): give 'address' and either " +
			"'length' (bytes) or 'end_address', then follow with create kind=instructions to " +
			"re-disassemble. kind=local_variable deletes the local variable 'variable_name' from " +
			"'function' (Ghidra's Delete Variable). kind=label deletes the user label at 'address' " +
			"(pass 'name' to pick one when several share the address). kind=function deletes the " +
			"function at 'function' but keeps its code and labels (Ghidra's Delete Function); to " +
			"recompute a stale body, delete then re-create with create kind=function. " +
			"kind=reference deletes the memory reference(s) from 'address' to 'to_address' " +
			"(all operand indexes, the inverse of create kind=reference).";
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
					"Function name or an address inside it (for kind=local_variable|function)"),
				"variable_name", Schemas.stringProp("Local variable to delete (for kind=local_variable)"),
				"name", Schemas.stringProp(
					"Which label to delete when several share the address (for kind=label)"),
				"to_address", Schemas.stringProp(
					"Reference target; deletes refs from 'address' to it (for kind=reference)")));
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
		return switch (kind) {
			case "local_variable" -> clearLocalVariable(program, args);
			case "label" -> clearLabel(program, args);
			case "function" -> clearFunction(program, args);
			case "reference" -> clearReference(program, args);
			default -> clearCode(program, args);
		};
	}

	private McpSchema.CallToolResult clearReference(Program program, Map<String, Object> args) {
		String addressArg = Args.stringArg(args, "address", null);
		String toArg = Args.stringArg(args, "to_address", null);
		if (addressArg == null || toArg == null) {
			return Results.error("'address' and 'to_address' are required for kind=reference");
		}
		Address from = Locations.parseAddress(program, addressArg);
		Address to = Locations.parseAddress(program, toArg);

		ReferenceManager refs = program.getReferenceManager();
		List<Reference> matches = new ArrayList<>();
		for (Reference ref : refs.getReferencesFrom(from)) {
			if (ref.getToAddress().equals(to)) {
				matches.add(ref);
			}
		}
		if (matches.isEmpty()) {
			return Results.error("No reference from " + from + " to " + to);
		}
		return Transactions.modify(program, "Delete reference", () -> {
			for (Reference ref : matches) {
				refs.delete(ref);
			}
			return "Deleted " + matches.size() + " reference(s) " + from + " -> " + to;
		});
	}

	private McpSchema.CallToolResult clearLabel(Program program, Map<String, Object> args) {
		String addressArg = Args.stringArg(args, "address", null);
		if (addressArg == null) {
			return Results.error("'address' is required for kind=label");
		}
		Address address = Locations.parseAddress(program, addressArg);
		String name = Args.stringArg(args, "name", null);

		Symbol[] symbols = program.getSymbolTable().getSymbols(address);
		List<Symbol> labels = new ArrayList<>();
		for (Symbol symbol : symbols) {
			if (symbol.getSymbolType() == SymbolType.LABEL && !symbol.isDynamic()) {
				labels.add(symbol);
			}
		}

		Symbol target;
		if (name != null) {
			target = labels.stream().filter(s -> s.getName().equals(name)).findFirst().orElse(null);
			if (target == null) {
				// A function symbol by that name would be silently removed by Symbol.delete() — guard.
				for (Symbol symbol : symbols) {
					if (symbol.getName().equals(name)
							&& symbol.getSymbolType() == SymbolType.FUNCTION) {
						return Results.error("'" + name + "' at " + address + " is a function symbol " +
							"— use kind=function to delete the function");
					}
				}
				return Results.error("No label named '" + name + "' at " + address);
			}
		}
		else if (labels.isEmpty()) {
			return Results.error("No user label at " + address);
		}
		else if (labels.size() > 1) {
			return Results.error("Multiple labels at " + address + " (" +
				labels.stream().map(Symbol::getName).reduce((a, b) -> a + ", " + b).orElse("") +
				") — pass 'name' to pick one");
		}
		else {
			target = labels.get(0);
		}

		Symbol toDelete = target;
		return Transactions.modify(program, "Delete label", () -> {
			String deleted = toDelete.getName();
			if (!toDelete.delete()) {
				throw new IllegalStateException("could not delete label '" + deleted + "'");
			}
			return "Deleted label '" + deleted + "' @ " + address;
		});
	}

	private McpSchema.CallToolResult clearFunction(Program program, Map<String, Object> args) {
		String functionRef = Args.stringArg(args, "function", null);
		if (functionRef == null) {
			return Results.error("'function' (a name or an address inside it) is required for " +
				"kind=function");
		}
		Function function = Locations.findFunction(program, functionRef);
		Address entry = function.getEntryPoint();
		String name = function.getName();
		return Transactions.modify(program, "Delete function", () -> {
			// DeleteFunctionCmd promotes local user labels to global and removes only the Function
			// object — instructions and labels are kept.
			if (!new DeleteFunctionCmd(entry).applyTo(program)) {
				throw new IllegalStateException("could not delete function at " + entry);
			}
			return "Deleted function " + name + " @ " + entry + " (code and labels kept)";
		});
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
