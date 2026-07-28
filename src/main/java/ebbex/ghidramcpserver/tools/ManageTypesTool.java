package ebbex.ghidramcpserver.tools;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import ebbex.ghidramcpserver.ProgramTool;
import ebbex.ghidramcpserver.util.Args;
import ebbex.ghidramcpserver.util.Results;
import ebbex.ghidramcpserver.util.Schemas;
import ebbex.ghidramcpserver.util.Transactions;
import ghidra.program.model.data.Composite;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.Undefined;
import ghidra.program.model.listing.Program;
import ghidra.util.data.DataTypeParser;
import ghidra.util.data.DataTypeParser.AllowedDataTypes;
import io.modelcontextprotocol.spec.McpSchema;

/**
 * Manage type definitions in the program's data type manager: rename or delete a type.
 *
 * <p>Complements the other type tools &mdash; {@code define_types} creates types (from a C
 * snippet) and {@code set_data_type} applies them to a location &mdash; neither of which can
 * rename or remove an existing type. Types are matched by simple name across all categories.
 */
public class ManageTypesTool implements ProgramTool {

	private static final List<String> OPS = List.of("rename", "delete", "rename_field", "set_field");

	/** How far either side of an edited offset to echo the layout back. */
	private static final int NEIGHBOURHOOD_BYTES = 16;

	@Override
	public String name() {
		return "manage_types";
	}

	@Override
	public String description() {
		return "Manage type definitions in the program's data type manager (types are created " +
			"with define_types and applied with set_data_type). op=rename renames the type 'name' " +
			"to 'new_name'. op=delete removes the type 'name' entirely; anything still using it " +
			"reverts to an undefined type. op=rename_field renames a field of the struct/union " +
			"'name' — identify the field by 'field' (its current name, or a byte offset like 0x1a) " +
			"and give the 'new_name'. op=set_field retypes whatever occupies 'offset' in the struct " +
			"'name' to 'type' (optionally naming it 'new_name') — this is how a struct is refined " +
			"a field at a time instead of re-declaring it whole: to split an 8-byte array into two " +
			"4-byte ones, set_field at its start and again at its midpoint. 'offset' need not be an " +
			"existing field's start, and the result echoes the surrounding fields plus any " +
			"undefined bytes the change left behind, so a split can be finished. 'name' matches by " +
			"simple type name across categories; if more than one matches, the call reports them " +
			"and does nothing.";
	}

	@Override
	public Map<String, Object> inputSchema() {
		return Map.of(
			"type", "object",
			"properties", Map.of(
				"op", Schemas.enumProp("Which action", OPS),
				"name", Schemas.stringProp("Current type name (simple name, e.g. \"colony\")"),
				"new_name", Schemas.stringProp("New name (type name for op=rename; field name for " +
					"op=rename_field; the new field's name, optional, for op=set_field)"),
				"field", Schemas.stringProp("Field to rename (current name, or byte offset like " +
					"0x1a) — for op=rename_field"),
				"offset", Schemas.stringProp("Byte offset into the struct where the field goes, " +
					"decimal or 0x-hex (e.g. 0xba) — for op=set_field. Need not be the start of " +
					"an existing field."),
				"type", Schemas.stringProp("The field's new type, with array or pointer syntax if " +
					"needed (e.g. \"byte[4]\", \"int\", \"colony *\") — for op=set_field"),
				"freeze_layout", Schemas.boolProp("For op=set_field on a struct with packing " +
					"enabled (which is how define_types creates them): turn packing off first, " +
					"keeping the offsets it currently has but making them fixed. Required before " +
					"a packed struct can be edited by offset; affects the whole type (default " +
					"false)")),
			"required", List.of("op", "name"));
	}

	@Override
	public boolean isReadOnly() {
		return false;
	}

	@Override
	public McpSchema.CallToolResult execute(Map<String, Object> args, Program program) {
		String op = Args.stringArg(args, "op", null);
		if (op == null || !OPS.contains(op)) {
			return Results.error("op must be one of " + OPS);
		}
		String name = Args.stringArg(args, "name", null);
		if (name == null || name.isBlank()) {
			return Results.error("'name' is required");
		}

		DataTypeManager dtm = program.getDataTypeManager();
		List<DataType> matches = new ArrayList<>();
		dtm.findDataTypes(name, matches);
		if (matches.isEmpty()) {
			return Results.error("No data type named '" + name + "'");
		}
		if (matches.size() > 1) {
			return Results.error("Ambiguous: " + matches.size() + " types named '" + name + "' (" +
				matches.stream().map(DataType::getPathName).collect(Collectors.joining(", ")) +
				"). Resolve the duplicate before renaming/deleting by simple name.");
		}
		DataType dataType = matches.get(0);

		return switch (op) {
			case "rename" -> rename(program, dataType, args);
			case "delete" -> delete(program, dtm, dataType);
			case "rename_field" -> renameField(program, dataType, args);
			case "set_field" -> setField(program, dataType, args);
			default -> Results.error("unhandled op " + op);
		};
	}

	private McpSchema.CallToolResult renameField(Program program, DataType dataType,
			Map<String, Object> args) {
		if (!(dataType instanceof Composite composite)) {
			return Results.error("'" + dataType.getName() + "' is not a struct/union; " +
				"op=rename_field needs a composite type");
		}
		String field = Args.stringArg(args, "field", null);
		String newName = Args.stringArg(args, "new_name", null);
		if (field == null || field.isBlank() || newName == null || newName.isBlank()) {
			return Results.error("'field' (current name or byte offset) and 'new_name' are " +
				"required for op=rename_field");
		}
		DataTypeComponent component = findComponent(composite, field);
		if (component == null) {
			return Results.error("No field '" + field + "' in " + composite.getName() +
				" (match by current field name or a byte offset like 0x1a)");
		}
		return Transactions.modify(program, "Rename struct field", () -> {
			String old = component.getFieldName();
			component.setFieldName(newName);
			return "Renamed field " +
				(old != null ? old : "+0x" + Integer.toHexString(component.getOffset())) + " -> " +
				newName + " in " + composite.getName();
		});
	}

	/**
	 * Retype (and optionally rename) whatever occupies a byte offset in a struct, so a record can
	 * be refined a field at a time as the RE lands — which is how struct knowledge actually
	 * arrives. Before this, the only ways to split one field into two were to re-declare the whole
	 * struct through {@code define_types} and re-apply it everywhere, or to leave the Ghidra type
	 * less precise than the C header it came from.
	 *
	 * <p>Placement is by offset, not by field name, because the interesting case is an offset that
	 * is <em>not</em> the start of a field: splitting an 8-byte {@code unkd[8]} into two 4-byte
	 * arrays means writing at the old field's start and then again at its midpoint.
	 */
	private McpSchema.CallToolResult setField(Program program, DataType dataType,
			Map<String, Object> args) {
		if (!(dataType instanceof Structure structure)) {
			return Results.error("'" + dataType.getName() + "' is not a struct" +
				(dataType instanceof Composite
						? " but a union, whose members all share offset 0 — there is no offset to " +
							"place a field at. Use op=rename_field for a union member."
						: " (it is " + dataType.getDisplayName() + "); op=set_field needs a " +
							"struct. define_types creates one."));
		}
		// Packing makes the caller's offset a lie: Ghidra recomputes every offset on repack, and an
		// offset that isn't inside an existing component is treated as an INSERT that shifts
		// everything after it. Silently relocating a record's fields is exactly the kind of
		// plausible-looking damage this tool exists to avoid — so it is refused, but with the way
		// out named, because a struct parsed from C by define_types is packed and that is precisely
		// the struct someone wants to refine.
		boolean freezeLayout = Args.boolArg(args, "freeze_layout", false);
		boolean wasPacked = structure.isPackingEnabled();
		if (wasPacked && !freezeLayout) {
			return Results.error("'" + structure.getName() + "' has packing enabled, so its field " +
				"offsets are computed rather than fixed, and op=set_field cannot honour the " +
				"'offset' you give: Ghidra recomputes it on repack, and an offset not inside an " +
				"existing field inserts and shifts everything after it. Pass freeze_layout=true to " +
				"turn packing off first — the offsets it currently has are kept exactly as they " +
				"are, they just stop being recomputed, which is what a byte-exact record layout " +
				"wants. Note that affects the whole type, not just this field.");
		}

		String offsetArg = Args.stringArg(args, "offset", null);
		Integer offset = offsetArg == null ? null : parseOffset(offsetArg);
		if (offset == null) {
			return Results.error("'offset' (a byte offset into " + structure.getName() +
				", decimal or 0x-hex) is required for op=set_field");
		}
		if (offset < 0 || offset >= structure.getLength()) {
			return Results.error("Offset +0x" + Integer.toHexString(offset) + " is outside " +
				structure.getName() + ", which is " + structure.getLength() + " (0x" +
				Integer.toHexString(structure.getLength()) + ") bytes long.");
		}
		String typeString = Args.stringArg(args, "type", null);
		if (typeString == null || typeString.isBlank()) {
			return Results.error("'type' is required for op=set_field (a type name, with array " +
				"syntax if needed, e.g. \"byte[4]\" or \"colony *\")");
		}
		DataType fieldType;
		try {
			DataTypeManager dtm = program.getDataTypeManager();
			fieldType = new DataTypeParser(dtm, dtm, null, AllowedDataTypes.ALL).parse(typeString);
		}
		catch (Exception e) {
			return Results.error("Could not parse type '" + typeString + "': " + e.getMessage());
		}
		if (fieldType == null || fieldType.getLength() <= 0) {
			return Results.error("Type '" + typeString + "' has no fixed size, so it cannot be " +
				"placed at an offset.");
		}
		String fieldName = Args.stringArg(args, "new_name", null);

		// Read what is there before the write, to report the replacement and to work out whether
		// the new field leaves a hole behind it.
		DataTypeComponent old = structure.getComponentContaining(offset);
		String replaced;
		if (old == null || Undefined.isUndefined(old.getDataType())) {
			// Filler rather than a field: a non-packed struct reports its gaps as undefined
			// components, and calling those an "unnamed field" overstates what was there.
			replaced = (old == null ? "undefined bytes" : plural(old.getLength(), "undefined byte")) +
				" at +0x" + Integer.toHexString(old == null ? offset : old.getOffset());
		}
		else {
			replaced = (old.getFieldName() != null ? old.getFieldName() : "an unnamed field") +
				" (" + old.getDataType().getName() + ", " + plural(old.getLength(), "byte") +
				" at +0x" + Integer.toHexString(old.getOffset()) + ")";
		}
		int holeStart = offset + fieldType.getLength();
		int holeEnd = old == null ? holeStart : old.getOffset() + old.getLength();

		return Transactions.modify(program, "Set struct field", () -> {
			StringBuilder sb = new StringBuilder();
			if (wasPacked) {
				// Offsets survive this: with packing off, repack() reconciles the existing
				// component offsets (adjustNonPackedComponents) instead of recomputing them, so
				// the layout is frozen exactly as it stands and gaps become undefined filler.
				structure.setPackingEnabled(false);
				sb.append("Turned packing OFF for ").append(structure.getName())
						.append(" — its current field offsets are now fixed rather than " +
							"recomputed. This affects every use of the type.\n");
			}
			structure.replaceAtOffset(offset, fieldType, -1, fieldName, null);
			sb.append("Set +0x").append(Integer.toHexString(offset)).append(" of ")
					.append(structure.getName()).append(" to ").append(fieldType.getName());
			if (fieldName != null && !fieldName.isBlank()) {
				sb.append(' ').append(fieldName);
			}
			sb.append(", replacing ").append(replaced).append('.');
			// Shrinking a field leaves undefined bytes where the rest of it was. Saying so is what
			// makes a two-step split (write the first half, then the second) finishable — silence
			// here reads as "done".
			if (holeEnd > holeStart) {
				sb.append("\nThat leaves ").append(plural(holeEnd - holeStart, "undefined byte"))
						.append(" at +0x").append(Integer.toHexString(holeStart))
						.append("..+0x").append(Integer.toHexString(holeEnd - 1))
						.append(" — the remainder of what was replaced. Set them with another " +
							"op=set_field if they are a field of their own.");
			}
			sb.append('\n').append(neighbourhood(structure, offset));
			return sb.toString();
		});
	}

	/**
	 * The defined fields around an offset, so the caller can see the result of the edit in context
	 * without a separate read — there is no tool that dumps a type's layout on its own.
	 */
	private static String neighbourhood(Structure structure, int offset) {
		StringBuilder sb = new StringBuilder(structure.getName() + " is now " +
			structure.getLength() + " bytes; fields near +0x" + Integer.toHexString(offset) + ":");
		int from = offset - NEIGHBOURHOOD_BYTES;
		int to = offset + NEIGHBOURHOOD_BYTES;
		boolean any = false;
		for (DataTypeComponent component : structure.getDefinedComponents()) {
			if (component.getOffset() < from || component.getOffset() > to) {
				continue;
			}
			any = true;
			sb.append("\n  +0x").append(Integer.toHexString(component.getOffset())).append(": ")
					.append(component.getDataType().getName());
			if (component.getFieldName() != null) {
				sb.append(' ').append(component.getFieldName());
			}
			sb.append("  (").append(plural(component.getLength(), "byte")).append(')');
			if (component.getOffset() == offset) {
				sb.append("  <-- just set");
			}
		}
		if (!any) {
			sb.append("\n  (no defined fields within 0x").append(
				Integer.toHexString(NEIGHBOURHOOD_BYTES)).append(" bytes)");
		}
		return sb.toString();
	}

	private static String plural(int count, String noun) {
		return count + " " + noun + (count == 1 ? "" : "s");
	}

	/** Locate a field by its current name, or by a byte offset given as decimal or 0x-hex. */
	private static DataTypeComponent findComponent(Composite composite, String field) {
		Integer offset = parseOffset(field);
		for (DataTypeComponent component : composite.getDefinedComponents()) {
			if (field.equals(component.getFieldName())) {
				return component;
			}
			if (offset != null && component.getOffset() == offset) {
				return component;
			}
		}
		return null;
	}

	private static Integer parseOffset(String s) {
		try {
			String t = s.trim();
			return t.regionMatches(true, 0, "0x", 0, 2) ? Integer.parseInt(t.substring(2), 16)
				: Integer.parseInt(t);
		}
		catch (NumberFormatException e) {
			return null;
		}
	}

	private McpSchema.CallToolResult rename(Program program, DataType dataType,
			Map<String, Object> args) {
		String newName = Args.stringArg(args, "new_name", null);
		if (newName == null || newName.isBlank()) {
			return Results.error("'new_name' is required for op=rename");
		}
		return Transactions.modify(program, "Rename data type", () -> {
			String old = dataType.getPathName();
			dataType.setName(newName);
			return "Renamed type " + old + " -> " + dataType.getPathName();
		});
	}

	private McpSchema.CallToolResult delete(Program program, DataTypeManager dtm,
			DataType dataType) {
		String path = dataType.getPathName();
		return Transactions.modify(program, "Delete data type", () -> {
			boolean removed = dtm.remove(dataType);
			return removed ? "Deleted type " + path
				: "Could not delete type " + path + " (still in use or protected)";
		});
	}
}
