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
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.listing.Program;
import io.modelcontextprotocol.spec.McpSchema;

/**
 * Manage type definitions in the program's data type manager: rename or delete a type.
 *
 * <p>Complements the other type tools &mdash; {@code define_types} creates types (from a C
 * snippet) and {@code set_data_type} applies them to a location &mdash; neither of which can
 * rename or remove an existing type. Types are matched by simple name across all categories.
 */
public class ManageTypesTool implements ProgramTool {

	private static final List<String> OPS = List.of("rename", "delete");

	@Override
	public String name() {
		return "manage_types";
	}

	@Override
	public String description() {
		return "Manage type definitions in the program's data type manager (types are created " +
			"with define_types and applied with set_data_type). op=rename renames the type 'name' " +
			"to 'new_name'. op=delete removes the type 'name' entirely; anything still using it " +
			"reverts to an undefined type. 'name' matches by simple type name across categories; " +
			"if more than one matches, the call reports them and does nothing.";
	}

	@Override
	public Map<String, Object> inputSchema() {
		return Map.of(
			"type", "object",
			"properties", Map.of(
				"op", Schemas.enumProp("Which action", OPS),
				"name", Schemas.stringProp("Current type name (simple name, e.g. \"colony\")"),
				"new_name", Schemas.stringProp("New type name (for op=rename)")),
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
			default -> Results.error("unhandled op " + op);
		};
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
