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
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.data.DataUtilities.ClearDataMode;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighFunctionDBUtil;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.data.DataTypeParser;
import ghidra.util.data.DataTypeParser.AllowedDataTypes;
import io.modelcontextprotocol.spec.McpSchema;

/** Apply a data type: define/retype data, a variable, a parameter, or a return type. */
public class SetDataTypeTool implements McpToolDef {

	private static final List<String> TARGETS =
		List.of("data", "local_variable", "parameter", "return");

	private final Decompilers decompilers;

	public SetDataTypeTool(Decompilers decompilers) {
		this.decompilers = decompilers;
	}

	@Override
	public String name() {
		return "set_data_type";
	}

	@Override
	public String description() {
		return "Apply a C data type. target=data defines/retypes data at 'address' (creating it " +
			"if the address is undefined). target=local_variable|parameter retypes the variable " +
			"'variable_name' in 'function'. target=return sets the return type of 'function'. " +
			"'type' is a C type string like 'int', 'char *', 'uint32_t[8]', or a known struct name.";
	}

	@Override
	public Map<String, Object> inputSchema() {
		return Map.of(
			"type", "object",
			"properties", Map.of(
				"target", Results.enumProp("What to type", TARGETS),
				"type", Results.stringProp("C data type string"),
				"address", Results.stringProp("Address (for target=data)"),
				"function", Results.stringProp(
					"Function name/address (for local_variable|parameter|return)"),
				"variable_name", Results.stringProp(
					"Variable name (for local_variable|parameter)")),
			"required", List.of("target", "type"));
	}

	@Override
	public boolean isReadOnly() {
		return false;
	}

	@Override
	public McpSchema.CallToolResult execute(Map<String, Object> args, Program program)
			throws Exception {
		String target = Results.stringArg(args, "target", null);
		String typeString = Results.stringArg(args, "type", null);
		if (target == null || !TARGETS.contains(target)) {
			return Results.error("target must be one of " + TARGETS);
		}
		if (typeString == null || typeString.isBlank()) {
			return Results.error("type is required");
		}

		DataType dataType = parseType(program, typeString);
		if (dataType == null) {
			return Results.error("Unknown data type: " + typeString);
		}

		return switch (target) {
			case "data" -> applyToData(program, args, dataType);
			case "return" -> applyToReturn(program, args, dataType);
			case "local_variable", "parameter" -> applyToVariable(program, args, dataType);
			default -> Results.error("unhandled target " + target);
		};
	}

	private McpSchema.CallToolResult applyToData(Program program, Map<String, Object> args,
			DataType dataType) {
		String addressArg = Results.stringArg(args, "address", null);
		if (addressArg == null) {
			return Results.error("address is required for target=data");
		}
		Address address = ProgramContext.parseAddress(program, addressArg);
		return Transactions.modify(program, "Set data type", () -> {
			DataUtilities.createData(program, address, dataType, -1,
				ClearDataMode.CLEAR_ALL_CONFLICT_DATA);
			return "Applied " + dataType.getName() + " @ " + address;
		});
	}

	private McpSchema.CallToolResult applyToReturn(Program program, Map<String, Object> args,
			DataType dataType) {
		String functionRef = Results.stringArg(args, "function", null);
		if (functionRef == null) {
			return Results.error("function is required for target=return");
		}
		Function function = ProgramContext.findFunction(program, functionRef);
		return Transactions.modify(program, "Set return type", () -> {
			function.setReturnType(dataType, SourceType.USER_DEFINED);
			return "Set return type of " + function.getName() + " to " + dataType.getName();
		});
	}

	private McpSchema.CallToolResult applyToVariable(Program program, Map<String, Object> args,
			DataType dataType) {
		String functionRef = Results.stringArg(args, "function", null);
		String variableName = Results.stringArg(args, "variable_name", null);
		if (functionRef == null || variableName == null) {
			return Results.error("function and variable_name are required");
		}
		Function function = ProgramContext.findFunction(program, functionRef);

		Variable dbVariable = findDbVariable(function, variableName);
		if (dbVariable != null) {
			return Transactions.modify(program, "Set variable type", () -> {
				dbVariable.setDataType(dataType, SourceType.USER_DEFINED);
				return "Set type of " + variableName + " to " + dataType.getName() + " in " +
					function.getName();
			});
		}

		HighSymbol highSymbol = findHighSymbol(program, function, variableName);
		if (highSymbol == null) {
			return Results.error("No variable named '" + variableName + "' in " +
				function.getName());
		}
		return Transactions.modify(program, "Set variable type", () -> {
			HighFunctionDBUtil.updateDBVariable(highSymbol, null, dataType,
				SourceType.USER_DEFINED);
			return "Set type of " + variableName + " to " + dataType.getName() + " in " +
				function.getName();
		});
	}

	private static DataType parseType(Program program, String typeString) throws Exception {
		DataTypeManager dtm = program.getDataTypeManager();
		DataTypeParser parser = new DataTypeParser(dtm, dtm, null, AllowedDataTypes.ALL);
		return parser.parse(typeString);
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
