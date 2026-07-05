package ebbex.ghidramcpserver.tools;

import java.util.List;
import java.util.Map;

import ebbex.ghidramcpserver.McpToolDef;
import ebbex.ghidramcpserver.util.Decompilers;
import ebbex.ghidramcpserver.util.ProgramContext;
import ebbex.ghidramcpserver.util.Results;
import ebbex.ghidramcpserver.util.Transactions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighFunctionDBUtil;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import io.modelcontextprotocol.spec.McpSchema;

/** Rename any nameable thing: function, label, data, parameter, or local variable. */
public class RenameTool implements McpToolDef {

	private static final List<String> TARGETS =
		List.of("function", "label", "data", "parameter", "local_variable");

	private final Decompilers decompilers;

	public RenameTool(Decompilers decompilers) {
		this.decompilers = decompilers;
	}

	@Override
	public String name() {
		return "rename";
	}

	@Override
	public String description() {
		return "Rename something. target=function|label|data renames the symbol at 'address' (or " +
			"the named function). target=parameter|local_variable renames a variable inside the " +
			"function given by 'function', identified by its current 'old_name'.";
	}

	@Override
	public Map<String, Object> inputSchema() {
		return Map.of(
			"type", "object",
			"properties", Map.of(
				"target", Results.enumProp("What to rename", TARGETS),
				"new_name", Results.stringProp("The new name"),
				"address", Results.stringProp(
					"Address of the function/label/data (for target=function|label|data)"),
				"function", Results.stringProp(
					"Function name or address (for target=parameter|local_variable)"),
				"old_name", Results.stringProp(
					"Current variable name (for target=parameter|local_variable)")),
			"required", List.of("target", "new_name"));
	}

	@Override
	public boolean isReadOnly() {
		return false;
	}

	@Override
	public McpSchema.CallToolResult execute(Map<String, Object> args, Program program) {
		String target = Results.stringArg(args, "target", null);
		String newName = Results.stringArg(args, "new_name", null);
		if (target == null || !TARGETS.contains(target)) {
			return Results.error("target must be one of " + TARGETS);
		}
		if (newName == null || newName.isBlank()) {
			return Results.error("new_name is required");
		}

		return switch (target) {
			case "function" -> renameFunction(program, args, newName);
			case "label", "data" -> renameSymbol(program, args, newName);
			case "parameter", "local_variable" -> renameVariable(program, args, newName);
			default -> Results.error("unhandled target " + target);
		};
	}

	private McpSchema.CallToolResult renameFunction(Program program, Map<String, Object> args,
			String newName) {
		String ref = Results.stringArg(args, "address",
			Results.stringArg(args, "function", null));
		if (ref == null) {
			return Results.error("address (or function) is required");
		}
		Function function = ProgramContext.findFunction(program, ref);
		return Transactions.modify(program, "Rename function", () -> {
			String old = function.getName();
			function.setName(newName, SourceType.USER_DEFINED);
			return "Renamed function " + old + " -> " + newName + " @ " +
				function.getEntryPoint();
		});
	}

	private McpSchema.CallToolResult renameSymbol(Program program, Map<String, Object> args,
			String newName) {
		String addressArg = Results.stringArg(args, "address", null);
		if (addressArg == null) {
			return Results.error("address is required");
		}
		Address address = ProgramContext.parseAddress(program, addressArg);
		Symbol symbol = program.getSymbolTable().getPrimarySymbol(address);
		if (symbol == null) {
			return Results.error("No symbol at " + address);
		}
		return Transactions.modify(program, "Rename symbol", () -> {
			String old = symbol.getName();
			symbol.setName(newName, SourceType.USER_DEFINED);
			return "Renamed " + old + " -> " + newName + " @ " + address;
		});
	}

	private McpSchema.CallToolResult renameVariable(Program program, Map<String, Object> args,
			String newName) {
		String functionRef = Results.stringArg(args, "function", null);
		String oldName = Results.stringArg(args, "old_name", null);
		if (functionRef == null || oldName == null) {
			return Results.error("function and old_name are required for variable renames");
		}
		Function function = ProgramContext.findFunction(program, functionRef);

		// Parameters and simple stack locals exist on the database function directly.
		Variable dbVariable = findDbVariable(function, oldName);
		if (dbVariable != null) {
			return Transactions.modify(program, "Rename variable", () -> {
				dbVariable.setName(newName, SourceType.USER_DEFINED);
				return "Renamed variable " + oldName + " -> " + newName + " in " +
					function.getName();
			});
		}

		// Otherwise resolve a decompiler HighSymbol (off the EDT), then apply in a transaction.
		HighSymbol highSymbol = findHighSymbol(program, function, oldName);
		if (highSymbol == null) {
			return Results.error("No parameter or local variable named '" + oldName + "' in " +
				function.getName());
		}
		return Transactions.modify(program, "Rename variable", () -> {
			HighFunctionDBUtil.updateDBVariable(highSymbol, newName, null,
				SourceType.USER_DEFINED);
			return "Renamed variable " + oldName + " -> " + newName + " in " + function.getName();
		});
	}

	private static Variable findDbVariable(Function function, String name) {
		for (Parameter parameter : function.getParameters()) {
			if (parameter.getName().equals(name)) {
				return parameter;
			}
		}
		for (Variable local : function.getLocalVariables()) {
			if (local.getName().equals(name)) {
				return local;
			}
		}
		return null;
	}

	private HighSymbol findHighSymbol(Program program, Function function, String name) {
		DecompileResults results = decompilers.decompile(program, function, 30);
		HighFunction high = results != null ? results.getHighFunction() : null;
		if (high == null) {
			return null;
		}
		return high.getLocalSymbolMap().getNameToSymbolMap().get(name);
	}
}
