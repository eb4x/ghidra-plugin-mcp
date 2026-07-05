package ebbex.ghidramcpserver.tools;

import java.util.List;
import java.util.Map;

import ebbex.ghidramcpserver.McpToolDef;
import ebbex.ghidramcpserver.util.ProgramContext;
import ebbex.ghidramcpserver.util.Results;
import ebbex.ghidramcpserver.util.Transactions;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.BookmarkManager;
import ghidra.program.model.listing.BookmarkType;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.task.TaskMonitor;
import io.modelcontextprotocol.spec.McpSchema;

/** Create a function, label, or bookmark at an address. */
public class CreateTool implements McpToolDef {

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
			"note bookmark ('name' is the category, 'comment' the text); kind=instructions " +
			"disassembles from the address (like pressing 'D'), e.g. after clear.";
	}

	@Override
	public Map<String, Object> inputSchema() {
		return Map.of(
			"type", "object",
			"properties", Map.of(
				"kind", Results.enumProp("What to create", KINDS),
				"address", Results.stringProp("Address to create at"),
				"name", Results.stringProp("Label/function name, or bookmark category"),
				"comment", Results.stringProp("Bookmark text (for kind=bookmark)")),
			"required", List.of("kind", "address"));
	}

	@Override
	public boolean isReadOnly() {
		return false;
	}

	@Override
	public McpSchema.CallToolResult execute(Map<String, Object> args, Program program) {
		String kind = Results.stringArg(args, "kind", null);
		String addressArg = Results.stringArg(args, "address", null);
		if (kind == null || !KINDS.contains(kind)) {
			return Results.error("kind must be one of " + KINDS);
		}
		if (addressArg == null) {
			return Results.error("address is required");
		}
		Address address = ProgramContext.parseAddress(program, addressArg);
		String label = Results.stringArg(args, "name", null);

		return switch (kind) {
			case "function" -> createFunction(program, address, label);
			case "label" -> createLabel(program, address, label);
			case "bookmark" -> createBookmark(program, address, label,
				Results.stringArg(args, "comment", ""));
			case "instructions" -> disassemble(program, address);
			default -> Results.error("unhandled kind " + kind);
		};
	}

	private McpSchema.CallToolResult createFunction(Program program, Address address,
			String name) {
		return Transactions.modify(program, "Create function", () -> {
			CreateFunctionCmd cmd = new CreateFunctionCmd(name, address, null,
				SourceType.USER_DEFINED);
			if (!cmd.applyTo(program, TaskMonitor.DUMMY)) {
				throw new IllegalStateException(cmd.getStatusMsg());
			}
			return "Created function @ " + address +
				(cmd.getFunction() != null ? " (" + cmd.getFunction().getName() + ")" : "");
		});
	}

	private McpSchema.CallToolResult createLabel(Program program, Address address, String name) {
		if (name == null || name.isBlank()) {
			return Results.error("name is required for kind=label");
		}
		return Transactions.modify(program, "Create label", () -> {
			program.getSymbolTable().createLabel(address, name, SourceType.USER_DEFINED);
			return "Created label '" + name + "' @ " + address;
		});
	}

	private McpSchema.CallToolResult createBookmark(Program program, Address address,
			String category, String comment) {
		return Transactions.modify(program, "Create bookmark", () -> {
			BookmarkManager manager = program.getBookmarkManager();
			manager.setBookmark(address, BookmarkType.NOTE,
				category == null ? "" : category, comment);
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
