package ebbex.ghidramcpserver.tools;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import ebbex.ghidramcpserver.ProgramTool;
import ebbex.ghidramcpserver.util.Args;
import ebbex.ghidramcpserver.util.Decompilers;
import ebbex.ghidramcpserver.util.Locations;
import ebbex.ghidramcpserver.util.Results;
import ebbex.ghidramcpserver.util.Schemas;
import ebbex.ghidramcpserver.util.Transactions;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.util.FillOutStructureHelper;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.data.DataUtilities.ClearDataMode;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighFunctionDBUtil;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.HighVariable;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.data.DataTypeParser;
import ghidra.util.data.DataTypeParser.AllowedDataTypes;
import ghidra.util.task.TaskMonitor;
import io.modelcontextprotocol.spec.McpSchema;

/** Apply a data type: define/retype data, a variable, a parameter, a return type, or a struct. */
public class SetDataTypeTool implements ProgramTool {

	private static final List<String> KINDS =
		List.of("data", "local_variable", "parameter", "return", "struct");

	private static final int DECOMPILE_TIMEOUT = 30;

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
		return "Apply a C data type. kind=data defines/retypes data at 'address' (creating it " +
			"if the address is undefined). kind=local_variable|parameter retypes the variable " +
			"'variable_name' in 'function'. kind=return sets the return type of 'function'. " +
			"'type' is a C type string like 'int', 'char *', 'uint32_t[8]', or a known struct name. " +
			"kind=struct declares 'variable_name' a struct pointer: supply a 'struct' layout " +
			"(name/size/fields, offset-based so packed layouts with gaps just work) to build and " +
			"apply it, or omit 'struct' to let the decompiler infer one from usage. A field with " +
			"'bits' set is a bitfield; consecutive bitfields sharing an 'offset' pack lsb-first " +
			"into that storage unit.";
	}

	@Override
	public Map<String, Object> inputSchema() {
		return Map.of(
			"type", "object",
			"properties", Map.of(
				"kind", Schemas.enumProp("What to type", KINDS),
				"type", Schemas.stringProp("C data type string (required except for kind=struct)"),
				"address", Schemas.stringProp("Address (for kind=data)"),
				"function", Schemas.stringProp("Function name or an address inside it " +
					"(for kind=local_variable|parameter|return|struct)"),
				"variable_name", Schemas.stringProp(
					"Variable name (for kind=local_variable|parameter|struct)"),
				"struct", structSchema(),
				"follow_calls", Schemas.boolProp(
					"kind=struct inferred: recurse into called functions (default true)")),
			"required", List.of("kind"));
	}

	private static Map<String, Object> structSchema() {
		return Map.of(
			"type", "object",
			"description", "kind=struct: supplied layout to build and apply; omit to auto-infer",
			"properties", Map.of(
				"name", Schemas.stringProp("Struct type name (default: generated unique name)"),
				"size", Schemas.intProp(
					"Total byte size (default: last field's end; supply to reserve trailing gap)"),
				"fields", Map.of(
					"type", "array",
					"description", "Fields at explicit byte offsets; gaps stay undefined bytes",
					"items", Map.of(
						"type", "object",
						"properties", Map.of(
							"offset", Schemas.intProp("Byte offset within the struct (for a " +
								"bitfield, the byte offset of its storage unit)"),
							"name", Schemas.stringProp("Field name"),
							"type", Schemas.stringProp("C type string, e.g. 'word', 'char[24]', " +
								"a struct name; for a bitfield the storage base type such as " +
								"'byte'/'word'/'dword'"),
							"bits", Schemas.intProp("If set, make a bitfield of this many bits; " +
								"consecutive bitfields sharing an 'offset' pack lsb-first")),
						"required", List.of("offset", "type")))));
	}

	@Override
	public boolean isReadOnly() {
		return false;
	}

	@Override
	public McpSchema.CallToolResult execute(Map<String, Object> args, Program program)
			throws Exception {
		String kind = Args.stringArg(args, "kind", null);
		if (kind == null || !KINDS.contains(kind)) {
			return Results.error("kind must be one of " + KINDS);
		}
		if (kind.equals("struct")) {
			return applyStruct(program, args);
		}

		String typeString = Args.stringArg(args, "type", null);
		if (typeString == null || typeString.isBlank()) {
			return Results.error("type is required");
		}
		DataType dataType = parseType(program, typeString);
		if (dataType == null) {
			return Results.error("Unknown data type: " + typeString);
		}

		return switch (kind) {
			case "data" -> applyToData(program, args, dataType);
			case "return" -> applyToReturn(program, args, dataType);
			case "local_variable", "parameter" -> applyToVariable(program, args, dataType);
			default -> Results.error("unhandled kind " + kind);
		};
	}

	private McpSchema.CallToolResult applyToData(Program program, Map<String, Object> args,
			DataType dataType) {
		String addressArg = Args.stringArg(args, "address", null);
		if (addressArg == null) {
			return Results.error("'address' is required for kind=data");
		}
		Address address = Locations.parseAddress(program, addressArg);
		return Transactions.modify(program, "Set data type", () -> {
			DataUtilities.createData(program, address, dataType, -1,
				ClearDataMode.CLEAR_ALL_CONFLICT_DATA);
			return "Applied " + dataType.getName() + " @ " + address;
		});
	}

	private McpSchema.CallToolResult applyToReturn(Program program, Map<String, Object> args,
			DataType dataType) {
		String functionRef = Args.stringArg(args, "function", null);
		if (functionRef == null) {
			return Results.error("'function' is required for kind=return");
		}
		Function function = Locations.findFunction(program, functionRef);
		return Transactions.modify(program, "Set return type", () -> {
			function.setReturnType(dataType, SourceType.USER_DEFINED);
			return "Set return type of " + function.getName() + " to " + dataType.getName();
		});
	}

	private McpSchema.CallToolResult applyToVariable(Program program, Map<String, Object> args,
			DataType dataType) {
		String functionRef = Args.stringArg(args, "function", null);
		String variableName = Args.stringArg(args, "variable_name", null);
		if (functionRef == null || variableName == null) {
			return Results.error("'function' and 'variable_name' are required");
		}
		Function function = Locations.findFunction(program, functionRef);
		VarTarget target = resolveVariable(program, function, variableName);
		if (target == null) {
			return Results.error("No variable named '" + variableName + "' in " +
				function.getName());
		}
		return Transactions.modify(program, "Set variable type", () -> {
			applyType(target, dataType);
			return "Set type of " + variableName + " to " + dataType.getName() + " in " +
				function.getName();
		});
	}

	/**
	 * kind=struct: declare {@code variable_name} a struct pointer. A supplied {@code struct}
	 * layout is built offset-by-offset; otherwise the decompiler infers one from how the
	 * pointer is used. Either way the struct is added to the DataTypeManager and the variable
	 * is retyped to {@code struct *} in a single transaction.
	 */
	private McpSchema.CallToolResult applyStruct(Program program, Map<String, Object> args) {
		String functionRef = Args.stringArg(args, "function", null);
		String variableName = Args.stringArg(args, "variable_name", null);
		if (functionRef == null || variableName == null) {
			return Results.error("'function' and 'variable_name' are required for kind=struct");
		}
		Function function = Locations.findFunction(program, functionRef);

		Map<String, Object> spec = asMap(args.get("struct"));
		boolean supplied = spec != null && (spec.get("fields") != null || spec.get("size") != null);

		Structure structure;
		VarTarget target;
		if (supplied) {
			try {
				structure = buildStruct(program, spec);
			}
			catch (Exception e) {
				return Results.error("Invalid struct layout: " + e.getMessage());
			}
			target = resolveVariable(program, function, variableName);
			if (target == null) {
				return Results.error("No variable named '" + variableName + "' in " +
					function.getName());
			}
		}
		else {
			Inferred inferred;
			try {
				inferred = inferStruct(program, function, variableName,
					Args.boolArg(args, "follow_calls", true));
			}
			catch (Exception e) {
				return Results.error("Struct inference failed: " + e.getMessage());
			}
			if (inferred == null) {
				return Results.error("Could not infer a structure for '" + variableName + "' in " +
					function.getName() + " — name an existing variable used as a pointer base, " +
					"or supply a 'struct' layout.");
			}
			structure = inferred.structure();
			target = new VarTarget(null, inferred.symbol());
		}

		Structure toStore = structure;
		VarTarget retypeTarget = target;
		return Transactions.modify(program, "Define struct and retype variable", () -> {
			DataTypeManager dtm = program.getDataTypeManager();
			Structure stored =
				(Structure) dtm.addDataType(toStore, DataTypeConflictHandler.DEFAULT_HANDLER);
			DataType pointer = dtm.addDataType(new PointerDataType(stored),
				DataTypeConflictHandler.DEFAULT_HANDLER);
			applyType(retypeTarget, pointer);
			return structSummary(stored, variableName, function);
		});
	}

	/** Build (but do not add) a Structure from a supplied offset-based field list. */
	private Structure buildStruct(Program program, Map<String, Object> spec) throws Exception {
		DataTypeManager dtm = program.getDataTypeManager();

		// bits > 0 marks a bitfield: 'type' is its storage base type and 'offset' the byte
		// offset of the storage unit it packs into.
		record Field(int offset, String name, DataType type, int bits) {
		}
		List<Field> fields = new ArrayList<>();
		int extent = 0;
		for (Map<String, Object> fs : asMapList(spec.get("fields"))) {
			if (!(fs.get("offset") instanceof Number offset)) {
				throw new IllegalArgumentException("each field needs an integer 'offset'");
			}
			String typeString = fs.get("type") != null ? fs.get("type").toString() : null;
			if (typeString == null || typeString.isBlank()) {
				throw new IllegalArgumentException("each field needs a 'type'");
			}
			DataType dt = parseType(program, typeString);
			if (dt == null) {
				throw new IllegalArgumentException("unknown field type: " + typeString);
			}
			int bits = fs.get("bits") instanceof Number b ? b.intValue() : 0;
			if (bits > dt.getLength() * 8) {
				throw new IllegalArgumentException("bitfield '" + fs.get("name") + "' wants " +
					bits + " bits but its " + typeString + " storage unit holds only " +
					dt.getLength() * 8);
			}
			String fieldName = fs.get("name") != null ? fs.get("name").toString() : null;
			fields.add(new Field(offset.intValue(), fieldName, dt, bits));
			extent = Math.max(extent, offset.intValue() + dt.getLength());
		}

		int size = extent;
		if (spec.get("size") instanceof Number n) {
			size = n.intValue();
			if (size < extent) {
				throw new IllegalArgumentException("size " + size +
					" is smaller than the fields require (" + extent + ")");
			}
		}
		if (size <= 0) {
			throw new IllegalArgumentException("struct needs a positive 'size' or at least one field");
		}

		CategoryPath category = new CategoryPath("/mcp");
		String name = spec.get("name") != null ? spec.get("name").toString() : null;
		if (name == null || name.isBlank()) {
			name = dtm.getUniqueName(category, "struct");
		}
		StructureDataType struct = new StructureDataType(category, name, size, dtm);
		// Consecutive bitfields sharing a storage unit (same byte offset) pack lsb-first.
		Map<Integer, Integer> bitCursor = new HashMap<>();
		for (Field f : fields) {
			if (f.bits() > 0) {
				int byteWidth = f.type().getLength();
				int bitOffset = bitCursor.getOrDefault(f.offset(), 0);
				if (bitOffset + f.bits() > byteWidth * 8) {
					throw new IllegalArgumentException("bitfields at offset 0x" +
						Integer.toHexString(f.offset()) + " overflow their " + byteWidth * 8 +
						"-bit storage unit");
				}
				struct.insertBitFieldAt(f.offset(), byteWidth, bitOffset, f.type(), f.bits(),
					f.name(), null);
				bitCursor.put(f.offset(), bitOffset + f.bits());
			}
			else {
				struct.replaceAtOffset(f.offset(), f.type(), f.type().getLength(), f.name(), null);
			}
		}
		return struct;
	}

	/** Result of inferring a struct: the built (unadded) Structure and the pointer's symbol. */
	private record Inferred(Structure structure, HighSymbol symbol) {
	}

	/** Infer a struct for {@code variableName} from decompiler usage (nothing added to the DB). */
	private Inferred inferStruct(Program program, Function function, String variableName,
			boolean followCalls) {
		return decompilers.withInterface(program, di -> {
			DecompileResults results =
				di.decompileFunction(function, DECOMPILE_TIMEOUT, TaskMonitor.DUMMY);
			HighFunction high = results != null ? results.getHighFunction() : null;
			if (high == null) {
				return null;
			}
			HighSymbol symbol = high.getLocalSymbolMap().getNameToSymbolMap().get(variableName);
			if (symbol == null) {
				return null;
			}
			HighVariable var = symbol.getHighVariable();
			if (var == null) {
				return null;
			}
			FillOutStructureHelper helper =
				new FillOutStructureHelper(program, TaskMonitor.DUMMY);
			// createNewStructure=true keeps processStructure fully in-memory: it builds a fresh
			// StructureDataType (no DB write, so no open transaction needed here) rather than
			// extending an existing DB struct. We add it + retype in the caller's transaction.
			// createClassIfNeeded=false: no C++ this-pointer class/namespace creation.
			Structure structure = helper.processStructure(var, function, true, false,
				followCalls ? di : null);
			return structure == null ? null : new Inferred(structure, symbol);
		});
	}

	private static String structSummary(Structure stored, String variableName, Function function) {
		StringBuilder sb = new StringBuilder();
		sb.append("Defined struct ").append(stored.getName())
			.append(" (").append(stored.getLength()).append(" bytes, ")
			.append(stored.getNumDefinedComponents()).append(" fields); ")
			.append(variableName).append(" in ").append(function.getName())
			.append(" is now ").append(stored.getName()).append(" *");
		DataTypeComponent[] components = stored.getDefinedComponents();
		int cap = Math.min(components.length, 40);
		for (int i = 0; i < cap; i++) {
			DataTypeComponent c = components[i];
			sb.append("\n  +0x").append(Integer.toHexString(c.getOffset()))
				.append(": ").append(c.getDataType().getName());
			if (c.getFieldName() != null) {
				sb.append(' ').append(c.getFieldName());
			}
		}
		if (components.length > cap) {
			sb.append("\n  … ").append(components.length - cap).append(" more");
		}
		return sb.toString();
	}

	private static DataType parseType(Program program, String typeString) throws Exception {
		DataTypeManager dtm = program.getDataTypeManager();
		DataTypeParser parser = new DataTypeParser(dtm, dtm, null, AllowedDataTypes.ALL);
		return parser.parse(typeString);
	}

	/** A variable to retype, resolved off the EDT: a DB variable or a decompiler symbol. */
	private record VarTarget(Variable dbVariable, HighSymbol highSymbol) {
	}

	private VarTarget resolveVariable(Program program, Function function, String name) {
		Variable dbVariable = findDbVariable(function, name);
		if (dbVariable != null) {
			return new VarTarget(dbVariable, null);
		}
		HighSymbol highSymbol = findHighSymbol(program, function, name);
		return highSymbol == null ? null : new VarTarget(null, highSymbol);
	}

	private static void applyType(VarTarget target, DataType dataType) throws Exception {
		if (target.dbVariable() != null) {
			target.dbVariable().setDataType(dataType, SourceType.USER_DEFINED);
		}
		else {
			HighFunctionDBUtil.updateDBVariable(target.highSymbol(), null, dataType,
				SourceType.USER_DEFINED);
		}
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
		DecompileResults results = decompilers.decompile(program, function, DECOMPILE_TIMEOUT);
		HighFunction high = results != null ? results.getHighFunction() : null;
		if (high == null) {
			return null;
		}
		return high.getLocalSymbolMap().getNameToSymbolMap().get(name);
	}

	@SuppressWarnings("unchecked")
	private static Map<String, Object> asMap(Object value) {
		return value instanceof Map<?, ?> m ? (Map<String, Object>) m : null;
	}

	@SuppressWarnings("unchecked")
	private static List<Map<String, Object>> asMapList(Object value) {
		if (value instanceof List<?> list) {
			return (List<Map<String, Object>>) list;
		}
		return List.of();
	}
}
