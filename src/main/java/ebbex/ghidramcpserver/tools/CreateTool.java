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
import ghidra.app.cmd.function.CreateThunkFunctionCmd;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.BookmarkManager;
import ghidra.program.model.listing.BookmarkType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.task.TaskMonitor;
import io.modelcontextprotocol.spec.McpSchema;

/** Create a function, label, or bookmark at an address. */
public class CreateTool implements ProgramTool {

	private static final List<String> KINDS =
		List.of("function", "label", "bookmark", "instructions", "thunk");

	@Override
	public String name() {
		return "create";
	}

	@Override
	public String description() {
		return "Create something at an address. kind=function disassembles/creates a function " +
			"(optional 'name'); kind=label adds a label ('name' required); kind=bookmark adds a " +
			"note bookmark (optional 'category', 'comment' is the text); kind=instructions " +
			"disassembles from the address (like pressing 'D'), e.g. after clear; kind=thunk makes " +
			"the function at 'address' a thunk of 'target' (name or address of the thunked function) " +
			"— for wiring un-thunked dispatch stubs to their real target.";
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
				"target", Schemas.stringProp(
					"Function this thunks to: a name or an address inside it (for kind=thunk)")),
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
			case "function" -> createFunction(program, address, label);
			case "label" -> createLabel(program, address, label);
			case "bookmark" -> createBookmark(program, address,
				Args.stringArg(args, "category", ""), Args.stringArg(args, "comment", ""));
			case "instructions" -> disassemble(program, address);
			case "thunk" -> createThunk(program, address, Args.stringArg(args, "target", null));
			default -> Results.error("unhandled kind " + kind);
		};
	}

	private McpSchema.CallToolResult createThunk(Program program, Address address, String targetRef) {
		if (targetRef == null || targetRef.isBlank()) {
			return Results.error("'target' (the function this thunks to) is required for kind=thunk");
		}
		Function target = Locations.findFunction(program, targetRef);
		return Transactions.modify(program, "Create thunk", () -> {
			Function existing = program.getFunctionManager().getFunctionAt(address);
			if (existing != null) {
				// Directly set the thunk relationship — CreateThunkFunctionCmd tries to infer the
				// thunk from the entry's instructions, which fails on unresolved-stub bad bytes.
				existing.setThunkedFunction(target);
				return "Set " + existing.getName() + " @ " + address + " as a thunk to " +
					target.getName() + " (" + target.getEntryPoint() + ")";
			}
			// No function yet at the address — create one that thunks the target.
			CreateThunkFunctionCmd cmd =
				new CreateThunkFunctionCmd(address, null, target.getEntryPoint());
			if (!cmd.applyTo(program, TaskMonitor.DUMMY)) {
				throw new IllegalStateException(cmd.getStatusMsg());
			}
			Function thunk = program.getFunctionManager().getFunctionAt(address);
			return "Created thunk @ " + address + " -> " + target.getName() +
				(thunk != null ? " (" + thunk.getName() + ")" : "");
		});
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
