package ebbex.ghidramcpserver.tools;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import ebbex.ghidramcpserver.ProgramTool;
import ebbex.ghidramcpserver.util.Args;
import ebbex.ghidramcpserver.util.Decompilers;
import ebbex.ghidramcpserver.util.Locations;
import ebbex.ghidramcpserver.util.Results;
import ebbex.ghidramcpserver.util.Schemas;
import ebbex.ghidramcpserver.util.Transactions;
import ebbex.ghidramcpserver.util.Variables;
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
import ghidra.program.model.data.MutabilitySettingsDefinition;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.listing.VariableUtilities;
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

	/** Ghidra's data mutability setting, in {@link MutabilitySettingsDefinition}'s order. */
	private static final List<String> MUTABILITIES =
		List.of("normal", "volatile", "constant", "writable");

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
			"if the address is undefined); 'mutability' sets Ghidra's per-item setting there, " +
			"e.g. constant for a never-written segment/table word so the decompiler folds its " +
			"value (with 'type' omitted it changes only the setting of the existing data). " +
			"kind=local_variable|parameter retypes the variable " +
			"'variable_name' in 'function'. kind=return sets the return type of 'function'. " +
			"'type' is a C type string like 'int', 'char *', 'uint32_t[8]', or a known struct name. " +
			"kind=struct declares 'variable_name' a struct pointer: supply a 'struct' layout " +
			"(name/size/fields, offset-based so packed layouts with gaps just work) to build and " +
			"apply it, or omit 'struct' to let the decompiler infer one from usage. A field with " +
			"'bits' set is a bitfield; consecutive bitfields sharing an 'offset' pack lsb-first " +
			"into that storage unit. Retyping a stack local to something larger fails with a " +
			"storage conflict when the decompiler had split that range into several locals; " +
			"the error maps each to its offset in the new type, and replace_overlapping=true " +
			"removes them and applies the type.";
	}

	@Override
	public Map<String, Object> inputSchema() {
		// Map.of stops at ten pairs; keep insertion order for a readable schema.
		Map<String, Object> properties = new LinkedHashMap<>();
		properties.put("kind", Schemas.enumProp("What to type", KINDS));
		properties.put("type",
			Schemas.stringProp("C data type string (required except for kind=struct)"));
		properties.put("address", Schemas.stringProp("Address (for kind=data)"));
		properties.put("mutability", Schemas.enumProp("kind=data: the data item's mutability " +
			"setting (constant = never written, so the decompiler may fold its value; volatile = " +
			"every access is kept; default: leave as is)", MUTABILITIES));
		properties.put("function", Schemas.stringProp("Function name or an address inside it " +
			"(for kind=local_variable|parameter|return|struct)"));
		properties.put("variable_name",
			Schemas.stringProp("Variable name (for kind=local_variable|parameter|struct)"));
		properties.put("pc", Schemas.stringProp("kind=local_variable: address of the instruction " +
			"that defines the variable, instead of 'variable_name' (decompile dump_symbols=true " +
			"prints it as pc=); only the merge group defined there is typed, splitting it out of " +
			"a merged variable"));
		properties.put("storage", Schemas.stringProp("With 'pc': which definition at that " +
			"instruction when there are several (a register name such as DX, or Stack[-0x10])"));
		properties.put("struct", structSchema());
		properties.put("follow_calls",
			Schemas.boolProp("kind=struct inferred: recurse into called functions (default true)"));
		properties.put("replace_overlapping", Schemas.boolProp("kind=local_variable|parameter: " +
			"remove the function's other variables whose storage the retyped one would now cover " +
			"(their names are lost; the result lists them with the offset each maps to in the " +
			"new type, for manage_types op=rename_field) (default false)"));
		return Map.of("type", "object", "properties", properties, "required", List.of("kind"));
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

		String mutability = Args.stringArg(args, "mutability", null);
		if (mutability != null && !MUTABILITIES.contains(mutability)) {
			return Results.error("mutability must be one of " + MUTABILITIES);
		}
		if (mutability != null && !kind.equals("data")) {
			return Results.error("'mutability' is a setting on defined data; it needs kind=data");
		}
		String typeString = Args.stringArg(args, "type", null);
		if (typeString == null || typeString.isBlank()) {
			if (mutability != null) {
				return setMutability(program, args, mutability);
			}
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
		String mutability = Args.stringArg(args, "mutability", null);
		return Transactions.modify(program, "Set data type", () -> {
			Data data = DataUtilities.createData(program, address, dataType, -1,
				ClearDataMode.CLEAR_ALL_CONFLICT_DATA);
			return "Applied " + dataType.getName() + " (" + data.getLength() + " bytes) @ " +
				address + " = " + data.getDefaultValueRepresentation() +
				applyMutability(data, mutability);
		});
	}

	/** kind=data with 'mutability' but no 'type': change the setting of the data already there. */
	private McpSchema.CallToolResult setMutability(Program program, Map<String, Object> args,
			String mutability) {
		String addressArg = Args.stringArg(args, "address", null);
		if (addressArg == null) {
			return Results.error("'address' is required for kind=data");
		}
		Address address = Locations.parseAddress(program, addressArg);
		Data data = program.getListing().getDefinedDataAt(address);
		if (data == null) {
			return Results.error("No defined data at " + address + " to set the mutability of; " +
				"give 'type' as well to define it first.");
		}
		return Transactions.modify(program, "Set data mutability",
			() -> data.getDataType().getName() + " (" + data.getLength() + " bytes) @ " + address +
				applyMutability(data, mutability));
	}

	/**
	 * Apply the setting the decompiler reads to decide whether a global's value may be folded
	 * ({@code constant}) or every access must be kept ({@code volatile}). It is a setting on the
	 * data instance, not on the type, so it survives a retype and the type stays shared.
	 */
	private static String applyMutability(Data data, String mutability) {
		if (mutability == null) {
			return "";
		}
		MutabilitySettingsDefinition.DEF.setChoice(data, MUTABILITIES.indexOf(mutability));
		return ", mutability " + MutabilitySettingsDefinition.DEF.getValueString(data);
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
			return "Set return type of " + function.getName() + " to " + dataType.getName() +
				" (" + dataType.getLength() + " bytes)";
		});
	}

	private McpSchema.CallToolResult applyToVariable(Program program, Map<String, Object> args,
			DataType dataType) {
		String functionRef = Args.stringArg(args, "function", null);
		String variableName = Args.stringArg(args, "variable_name", null);
		if (functionRef == null || (variableName == null && args.get("pc") == null)) {
			return Results.error("'function' and 'variable_name' (or 'pc') are required");
		}
		Function function = Locations.findFunction(program, functionRef);
		boolean replaceOverlapping = Args.boolArg(args, "replace_overlapping", false);
		String pcArg = Args.stringArg(args, "pc", null);
		if (pcArg != null) {
			return applyByPc(program, function, Locations.parseAddress(program, pcArg),
				Args.stringArg(args, "storage", null), dataType, replaceOverlapping);
		}
		VarTarget target = resolveVariable(program, function, variableName);
		if (target == null) {
			return Results.error("No variable named '" + variableName + "' in " +
				function.getName() + " (the decompiler renumbers its temporaries after every " +
				"edit; address one by 'pc', the defining instruction, which does not move)");
		}
		return Transactions.modify(program, "Set variable type", () -> {
			List<Variable> overlapping = overlapping(function, target, dataType);
			// Described before anything is removed: a deleted variable's symbol no longer has
			// a name to print, and the names are the whole point of the report.
			String covered = overlapMap(target, overlapping);
			String removed = "";
			if (!overlapping.isEmpty() && replaceOverlapping) {
				for (Variable other : overlapping) {
					function.removeVariable(other);
				}
				removed = "\nRemoved " + overlapping.size() + " overlapping variable(s): " + covered;
			}
			else if (!overlapping.isEmpty() && target.highSymbol() != null) {
				// Ghidra deletes these without a word when the symbol is committed (a type
				// lock on a DX:AX call result took the DX:2 symbol beside it). Stop first.
				throw new Exception("committing this symbol would remove " + overlapping.size() +
					" existing variable(s) whose storage it overlaps: " + covered +
					". Pass replace_overlapping=true to accept that, or clear them first.");
			}
			Map<Long, String> before = Variables.snapshot(function);
			try {
				applyType(target, dataType);
			}
			catch (Exception e) {
				if (overlapping.isEmpty() || replaceOverlapping) {
					throw e;
				}
				// Ghidra's own message lists storage ranges; what the caller needs is which
				// field of the new type each old local was, so the rename can carry over.
				throw new Exception(e.getMessage() + "\nThe new type (" + dataType.getLength() +
					" bytes) covers " + covered + ". Pass " +
					"replace_overlapping=true to remove them and apply the type; then name the " +
					"fields with manage_types op=rename_field.");
			}
			return "Set type of " + variableName + " to " + dataType.getName() + " (" +
				dataType.getLength() + " bytes) in " + function.getName() + removed +
				autoNameNote(target.highSymbol(), variableName) + removedNote(function, before);
		});
	}

	/**
	 * Type the variable defined at one instruction. The definition's merge group is split out
	 * of a speculative merge first (Ghidra's Split Out As New Variable), so the lock lands on
	 * the role the caller pointed at rather than on whichever varnode is the representative.
	 */
	private McpSchema.CallToolResult applyByPc(Program program, Function function, Address pc,
			String storage, DataType dataType, boolean replaceOverlapping) {
		Variables.HighTarget target = Variables.findByPc(decompilers, program, function, pc, storage);
		return Transactions.modify(program, "Set variable type", () -> {
			String oldName = target.variable().getName();
			int group = target.groupSize();
			int all = target.instanceCount();
			HighVariable peeled = Variables.split(target);
			HighSymbol symbol = peeled.getSymbol();
			VariableStorage resized = symbol.getStorage();
			try {
				resized = VariableUtilities.resizeStorage(symbol.getStorage(), dataType, true,
					function);
			}
			catch (Exception e) {
				// Ghidra will say so itself when it commits; the overlap check uses what it can.
			}
			List<Variable> hits =
				Variables.intersecting(function, resized, symbol.getPCAddress(), null);
			String removed = "";
			if (!hits.isEmpty() && !replaceOverlapping) {
				throw new Exception("committing this symbol would remove " + hits.size() +
					" existing variable(s) whose storage it overlaps: " +
					Variables.describe(function, hits) +
					". Pass replace_overlapping=true to accept that, or clear them first.");
			}
			if (!hits.isEmpty()) {
				for (Variable other : hits) {
					function.removeVariable(other);
				}
				removed = "\nRemoved " + hits.size() + " overlapping variable(s): " +
					Variables.describe(function, hits);
			}
			Map<Long, String> before = Variables.snapshot(function);
			HighFunctionDBUtil.updateDBVariable(symbol, null, dataType, SourceType.USER_DEFINED);
			String where = Variables.storageText(target.high(), program, target.varnode()) +
				" defined at " + pc;
			String split = group < all
					? "split " + group + " of " + all + " instances of " + oldName +
						" out as their own variable"
					: "all " + all + " instances of " + oldName;
			return "Set type " + dataType.getName() + " (" + dataType.getLength() + " bytes) on " +
				where + " (" + split + ")" + removed + autoNameNote(symbol, symbol.getName()) +
				removedNote(function, before);
		});
	}

	/**
	 * A type lock turns the decompiler's throwaway name into a USER_DEFINED symbol that still
	 * looks like a temporary, and nothing downstream can tell the two apart. Say so.
	 */
	private static String autoNameNote(HighSymbol symbol, String name) {
		if (symbol == null || !Variables.isAutoName(name)) {
			return "";
		}
		return "\nNote: the symbol keeps the decompiler's name '" + name + "' but is now a " +
			"user symbol with a locked type; rename it (rename kind=local_variable pc=...) or " +
			"clear it so it does not pass for a temporary.";
	}

	private static String removedNote(Function function, Map<Long, String> before) {
		List<String> removed = Variables.removedSince(function, before);
		return removed.isEmpty() ? ""
				: "\nRemoved by Ghidra as overlapping: " + String.join(", ", removed);
	}

	/**
	 * The function's other variables whose storage the target would cover once retyped.
	 * The decompiler splits an untyped stack buffer into one local per accessed slot, so a
	 * struct laid over it collides with every one of them; empty when the new storage cannot
	 * be computed (register locals, hash storage).
	 */
	private static List<Variable> overlapping(Function function, VarTarget target,
			DataType dataType) {
		VariableStorage storage = target.dbVariable() != null
				? target.dbVariable().getVariableStorage()
				: target.highSymbol().getStorage();
		VariableStorage resized;
		try {
			resized = VariableUtilities.resizeStorage(storage, dataType, true, function);
		}
		catch (Exception e) {
			return List.of();
		}
		List<Variable> hits = new ArrayList<>();
		for (Variable other : function.getAllVariables()) {
			if (other.equals(target.dbVariable())) {
				continue;
			}
			if (other.getVariableStorage().intersects(resized)) {
				hits.add(other);
			}
		}
		return hits;
	}

	/** {@code local_80 (undefined2 @ Stack[-0x80] = +0x96 in the new type), …}. */
	private static String overlapMap(VarTarget target, List<Variable> overlapping) {
		VariableStorage storage = target.dbVariable() != null
				? target.dbVariable().getVariableStorage()
				: target.highSymbol().getStorage();
		boolean stack = storage.isStackStorage();
		long base = stack ? storage.getStackOffset() : 0;
		List<String> parts = new ArrayList<>();
		for (Variable other : overlapping) {
			String where = other.getVariableStorage().toString();
			if (stack && other.isStackVariable()) {
				long delta = other.getStackOffset() - base;
				where += " = " + (delta < 0 ? "-0x" + Long.toHexString(-delta)
						: "+0x" + Long.toHexString(delta)) + " in the new type";
			}
			parts.add(other.getName() + " (" + other.getDataType().getName() + " @ " + where + ")");
		}
		return String.join(", ", parts);
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
		Variable dbVariable = Variables.findDbVariable(function, name);
		if (dbVariable != null) {
			return new VarTarget(dbVariable, null);
		}
		HighSymbol highSymbol = Variables.findHighSymbol(decompilers, program, function, name);
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
