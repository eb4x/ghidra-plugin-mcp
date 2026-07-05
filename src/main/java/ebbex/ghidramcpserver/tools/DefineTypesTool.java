package ebbex.ghidramcpserver.tools;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import ebbex.ghidramcpserver.ProgramTool;
import ebbex.ghidramcpserver.util.Args;
import ebbex.ghidramcpserver.util.Results;
import ebbex.ghidramcpserver.util.Schemas;
import ghidra.app.util.cparser.C.CParser;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.listing.Program;
import io.modelcontextprotocol.spec.McpSchema;

/**
 * Define data types (structs, unions, typedefs, enums) into the program's data
 * type manager from a C source snippet. Lets you materialize types like a 16-bit
 * {@code FILE} so they can then be used by set_function_signature / set_data_type.
 */
public class DefineTypesTool implements ProgramTool {

	@Override
	public String name() {
		return "define_types";
	}

	@Override
	public String description() {
		return "Parse a C source snippet (structs, unions, typedefs, enums) into the program's " +
			"data type manager. Example: 'typedef struct { int handle; char *buf; int flags; } " +
			"FILE;'. The created types can then be referenced by set_function_signature and " +
			"set_data_type.";
	}

	@Override
	public Map<String, Object> inputSchema() {
		return Map.of(
			"type", "object",
			"properties", Map.of(
				"source", Schemas.stringProp("C declarations to parse into the program")),
			"required", List.of("source"));
	}

	@Override
	public boolean isReadOnly() {
		return false;
	}

	@Override
	public McpSchema.CallToolResult execute(Map<String, Object> args, Program program)
			throws Exception {
		String source = Args.stringArg(args, "source", null);
		if (source == null || source.isBlank()) {
			return Results.error("source is required");
		}

		DataTypeManager dtm = program.getDataTypeManager();
		// CParser writes into the DTM inside its own transaction (storeDataType=true).
		CParser parser = new CParser(dtm, true, new DataTypeManager[0]);
		try {
			parser.parse(source);
		}
		catch (Exception e) {
			return Results.error("Failed to parse C declarations: " + e.getMessage());
		}

		List<String> created = new ArrayList<>();
		parser.getComposites().keySet().forEach(n -> created.add("struct/union " + n));
		parser.getTypes().keySet().forEach(n -> created.add("typedef " + n));
		parser.getEnums().keySet().forEach(n -> created.add("enum " + n));

		if (created.isEmpty()) {
			return Results.ok("Parsed successfully, but no named types were produced.");
		}
		return Results.ok("Defined " + created.size() + " type(s):\n  " +
			String.join("\n  ", created));
	}
}
