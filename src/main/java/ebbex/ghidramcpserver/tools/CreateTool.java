package ebbex.ghidramcpserver.tools;

import java.util.List;
import java.util.Map;

import ebbex.ghidramcpserver.ProgramTool;
import ebbex.ghidramcpserver.util.Args;
import ebbex.ghidramcpserver.util.Locations;
import ebbex.ghidramcpserver.util.Results;
import ebbex.ghidramcpserver.util.Schemas;
import ebbex.ghidramcpserver.util.Transactions;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.BookmarkManager;
import ghidra.program.model.listing.BookmarkType;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.task.TaskMonitor;
import io.modelcontextprotocol.spec.McpSchema;

/** Create a function, label, or bookmark at an address. */
public class CreateTool implements ProgramTool {

	private static final List<String> KINDS =
		List.of("function", "label", "bookmark", "instructions");

	@Override
	public String name() {
		return "create";
	}

	@Override
	public String description() {
		return "Create something at an address. kind=function disassembles/creates a function " +
			"(optional 'name'); kind=label adds a label ('name' required); kind=bookmark adds a " +
			"note bookmark (optional 'category', 'comment' is the text); kind=instructions " +
			"disassembles from the address (like pressing 'D'), e.g. after clear. For kind=function " +
			"an optional 'end_address' forces the body to that inclusive range (works on an existing " +
			"function too); omit it to auto-compute from flow. For kind=label an optional " +
			"'namespace' ('::'-separated path, e.g. \"main::override\") puts the label in that " +
			"namespace, creating missing levels.";
	}

	@Override
	public Map<String, Object> inputSchema() {
		return Map.of(
			"type", "object",
			"properties", Map.of(
				"kind", Schemas.enumProp("What to create", KINDS),
				"address", Schemas.stringProp("Address to create at"),
				"name", Schemas.stringProp("Label or function name (for kind=function|label)"),
				"category", Schemas.stringProp("Bookmark category (for kind=bookmark)"),
				"comment", Schemas.stringProp("Bookmark text (for kind=bookmark)"),
				"end_address", Schemas.stringProp(
					"Inclusive end address forcing the function body range (for kind=function)"),
				"namespace", Schemas.stringProp(
					"'::'-separated namespace path for the label (for kind=label)")),
			"required", List.of("kind", "address"));
	}

	@Override
	public boolean isReadOnly() {
		return false;
	}

	@Override
	public McpSchema.CallToolResult execute(Map<String, Object> args, Program program) {
		String kind = Args.stringArg(args, "kind", null);
		String addressArg = Args.stringArg(args, "address", null);
		if (kind == null || !KINDS.contains(kind)) {
			return Results.error("kind must be one of " + KINDS);
		}
		if (addressArg == null) {
			return Results.error("address is required");
		}
		Address address = Locations.parseAddress(program, addressArg);
		String label = Args.stringArg(args, "name", null);

		return switch (kind) {
			case "function" -> createFunction(program, address, label,
				Args.stringArg(args, "end_address", null));
			case "label" -> createLabel(program, address, label,
				Args.stringArg(args, "namespace", null));
			case "bookmark" -> createBookmark(program, address,
				Args.stringArg(args, "category", ""), Args.stringArg(args, "comment", ""));
			case "instructions" -> disassemble(program, address);
			default -> Results.error("unhandled kind " + kind);
		};
	}

	private McpSchema.CallToolResult createFunction(Program program, Address address,
			String name, String endArg) {
		AddressSetView body = null;
		if (endArg != null && !endArg.isBlank()) {
			body = new AddressSet(address, Locations.parseAddress(program, endArg));
		}
		AddressSetView functionBody = body;
		return Transactions.modify(program, "Create function", () -> {
			// With an explicit body, recreateFunction=true so it applies even to an existing
			// function (setBody); without one, auto-compute the body from flow as before.
			CreateFunctionCmd cmd = functionBody != null
					? new CreateFunctionCmd(name, address, functionBody, SourceType.USER_DEFINED,
						false, true)
					: new CreateFunctionCmd(name, address, null, SourceType.USER_DEFINED);
			if (!cmd.applyTo(program, TaskMonitor.DUMMY)) {
				throw new IllegalStateException(cmd.getStatusMsg());
			}
			String named = cmd.getFunction() != null ? " (" + cmd.getFunction().getName() + ")" : "";
			String bodyNote = functionBody != null
					? ", body " + functionBody.getNumAddresses() + " bytes"
					: "";
			return "Created function @ " + address + named + bodyNote;
		});
	}

	private McpSchema.CallToolResult createLabel(Program program, Address address, String name,
			String namespacePath) {
		if (name == null || name.isBlank()) {
			return Results.error("name is required for kind=label");
		}
		return Transactions.modify(program, "Create label", () -> {
			SymbolTable symbolTable = program.getSymbolTable();
			Namespace namespace = resolveNamespace(program, namespacePath);
			symbolTable.createLabel(address, name, namespace, SourceType.USER_DEFINED);
			String where = namespace.isGlobal() ? "" : " in " + namespace.getName(true);
			return "Created label '" + name + "'" + where + " @ " + address;
		});
	}

	/**
	 * Walk (creating as needed) a {@code ::}-separated namespace path from the global namespace.
	 * An existing function is itself a namespace, so paths may descend into one.
	 */
	private Namespace resolveNamespace(Program program, String path) throws Exception {
		Namespace namespace = program.getGlobalNamespace();
		if (path == null || path.isBlank()) {
			return namespace;
		}
		SymbolTable symbolTable = program.getSymbolTable();
		for (String part : path.split("::")) {
			if (part.isBlank()) {
				continue;
			}
			Namespace child = symbolTable.getNamespace(part, namespace);
			if (child == null) {
				child = symbolTable.createNameSpace(namespace, part, SourceType.USER_DEFINED);
			}
			namespace = child;
		}
		return namespace;
	}

	private McpSchema.CallToolResult createBookmark(Program program, Address address,
			String category, String comment) {
		return Transactions.modify(program, "Create bookmark", () -> {
			BookmarkManager manager = program.getBookmarkManager();
			manager.setBookmark(address, BookmarkType.NOTE, category, comment);
			return "Created bookmark @ " + address;
		});
	}

	private McpSchema.CallToolResult disassemble(Program program, Address address) {
		return Transactions.modify(program, "Disassemble", () -> {
			DisassembleCommand cmd = new DisassembleCommand(address, null, true);
			if (!cmd.applyTo(program, TaskMonitor.DUMMY)) {
				throw new IllegalStateException(cmd.getStatusMsg());
			}
			long bytes = cmd.getDisassembledAddressSet() != null
					? cmd.getDisassembledAddressSet().getNumAddresses()
					: 0;
			return "Disassembled from " + address + " (" + bytes + " bytes)";
		});
	}
}
