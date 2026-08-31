package ebbex.ghidramcpserver.tools;

import java.util.ArrayList;
import java.util.LinkedHashMap;
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
import ghidra.app.util.NamespaceUtils;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.BookmarkManager;
import ghidra.program.model.listing.BookmarkType;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.symbol.SymbolType;
import ghidra.util.task.TaskMonitor;
import io.modelcontextprotocol.spec.McpSchema;

/** Create a function, label, bookmark, instructions, or reference at an address. */
public class CreateTool implements ProgramTool {

	private static final List<String> KINDS =
		List.of("function", "label", "bookmark", "instructions", "reference",
			"functions_at_labels");

	/** How many created/skipped names the functions_at_labels summary spells out. */
	private static final int MAX_NAMED = 50;

	/** ref_type values accepted by kind=reference, mapped to Ghidra's RefType constants. */
	private static final Map<String, RefType> REF_TYPES = new LinkedHashMap<>();
	static {
		REF_TYPES.put("computed_jump", RefType.COMPUTED_JUMP);
		REF_TYPES.put("conditional_jump", RefType.CONDITIONAL_JUMP);
		REF_TYPES.put("unconditional_jump", RefType.UNCONDITIONAL_JUMP);
		REF_TYPES.put("computed_call", RefType.COMPUTED_CALL);
		REF_TYPES.put("conditional_call", RefType.CONDITIONAL_CALL);
		REF_TYPES.put("unconditional_call", RefType.UNCONDITIONAL_CALL);
		REF_TYPES.put("read", RefType.READ);
		REF_TYPES.put("write", RefType.WRITE);
		REF_TYPES.put("read_write", RefType.READ_WRITE);
		REF_TYPES.put("data", RefType.DATA);
		REF_TYPES.put("indirection", RefType.INDIRECTION);
	}

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
			"namespace, creating missing levels. kind=reference adds a memory reference from " +
			"'address' to 'to_address' with 'ref_type' (e.g. computed_jump for hand-applied " +
			"jump-table targets); optional 'operand_index' ties it to an operand (default: the " +
			"mnemonic). kind=functions_at_labels takes no address: it creates a function at every " +
			"user/imported-named label that sits in executable memory on no defined data and " +
			"starts no function yet (the OMF PUBDEF case — entry points that import as plain " +
			"labels); the label becomes the function's name.";
	}

	@Override
	public Map<String, Object> inputSchema() {
		Map<String, Object> properties = new LinkedHashMap<>();
		properties.put("kind", Schemas.enumProp("What to create", KINDS));
		properties.put("address", Schemas.stringProp(
			"Address to create at (for kind=reference: the from/source address; not used by " +
			"kind=functions_at_labels)"));
		properties.put("name",
			Schemas.stringProp("Label or function name (for kind=function|label)"));
		properties.put("category", Schemas.stringProp("Bookmark category (for kind=bookmark)"));
		properties.put("comment", Schemas.stringProp("Bookmark text (for kind=bookmark)"));
		properties.put("end_address", Schemas.stringProp(
			"Inclusive end address forcing the function body range (for kind=function)"));
		properties.put("namespace", Schemas.stringProp(
			"'::'-separated namespace path for the label (for kind=label)"));
		properties.put("to_address",
			Schemas.stringProp("Reference target address (for kind=reference)"));
		properties.put("ref_type", Schemas.enumProp(
			"Reference type (for kind=reference)", List.copyOf(REF_TYPES.keySet())));
		properties.put("operand_index", Schemas.intProp(
			"Operand the reference hangs off, 0-based (for kind=reference; default: mnemonic)"));
		return Map.of(
			"type", "object",
			"properties", properties,
			"required", List.of("kind"));
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
		if (kind.equals("functions_at_labels")) {
			return createFunctionsAtLabels(program);
		}
		if (addressArg == null) {
			return Results.error("address is required for kind=" + kind);
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
			case "reference" -> createReference(program, address,
				Args.stringArg(args, "to_address", null), Args.stringArg(args, "ref_type", null),
				Args.intArg(args, "operand_index", CodeUnit.MNEMONIC));
			default -> Results.error("unhandled kind " + kind);
		};
	}

	/**
	 * Promote every trusted label in code to a function. "Trusted" is the FID analyzer's own
	 * bar — USER_DEFINED or IMPORTED — so analysis-made labels (LAB_, switch cases) are left
	 * alone. A label inside another function's body is still a function start (the earlier
	 * function's flow simply ran through it), so only a function <em>starting</em> at the
	 * label disqualifies it; CreateFunctionCmd splits the body as it would from the GUI.
	 */
	private McpSchema.CallToolResult createFunctionsAtLabels(Program program) {
		return Transactions.modify(program, "Create functions at labels", () -> {
			List<String> created = new ArrayList<>();
			List<String> onData = new ArrayList<>();
			List<String> failed = new ArrayList<>();
			int existing = 0;
			int notCode = 0;
			// Snapshot first: creating functions mutates the symbol table under an iterator.
			List<Symbol> labels = new ArrayList<>();
			for (Symbol symbol : program.getSymbolTable().getAllSymbols(false)) {
				if (symbol.getSymbolType() != SymbolType.LABEL || symbol.isExternal()) {
					continue;
				}
				if (!symbol.getSource().isHigherOrEqualPriorityThan(SourceType.IMPORTED)) {
					continue;
				}
				labels.add(symbol);
			}
			for (Symbol symbol : labels) {
				Address address = symbol.getAddress();
				if (!address.isMemoryAddress()) {
					continue;
				}
				MemoryBlock block = program.getMemory().getBlock(address);
				if (block == null || !block.isExecute()) {
					notCode++;
					continue;
				}
				if (program.getFunctionManager().getFunctionAt(address) != null) {
					existing++;
					continue;
				}
				if (program.getListing().getDefinedDataContaining(address) != null) {
					onData.add(symbol.getName() + " @ " + address);
					continue;
				}
				CreateFunctionCmd cmd =
					new CreateFunctionCmd(null, address, null, SourceType.USER_DEFINED);
				if (cmd.applyTo(program, TaskMonitor.DUMMY)) {
					Function function = program.getFunctionManager().getFunctionAt(address);
					created.add((function != null ? function.getName() : symbol.getName()) +
						" @ " + address);
				}
				else {
					failed.add(symbol.getName() + " @ " + address + ": " + cmd.getStatusMsg());
				}
			}
			StringBuilder sb = new StringBuilder();
			sb.append("Created ").append(created.size()).append(" function(s) at ")
					.append(labels.size()).append(" user/imported label(s); skipped ")
					.append(existing).append(" already function starts, ")
					.append(onData.size()).append(" on defined data, ")
					.append(notCode).append(" outside executable memory")
					.append(failed.isEmpty() ? "." : ", " + failed.size() + " failed.");
			appendNames(sb, "Created", created);
			appendNames(sb, "On data (not created)", onData);
			appendNames(sb, "Failed", failed);
			return sb.toString();
		});
	}

	private static void appendNames(StringBuilder sb, String heading, List<String> names) {
		if (names.isEmpty()) {
			return;
		}
		sb.append('\n').append(heading).append(": ");
		sb.append(String.join(", ", names.subList(0, Math.min(names.size(), MAX_NAMED))));
		if (names.size() > MAX_NAMED) {
			sb.append(", ... ").append(names.size() - MAX_NAMED).append(" more");
		}
	}

	private McpSchema.CallToolResult createReference(Program program, Address from, String toArg,
			String refTypeArg, int operandIndex) {
		if (toArg == null || toArg.isBlank()) {
			return Results.error("'to_address' is required for kind=reference");
		}
		RefType refType = refTypeArg != null ? REF_TYPES.get(refTypeArg) : null;
		if (refType == null) {
			return Results.error("ref_type must be one of " + REF_TYPES.keySet());
		}
		Address to = Locations.parseAddress(program, toArg);
		return Transactions.modify(program, "Create reference", () -> {
			Reference reference = program.getReferenceManager()
					.addMemoryReference(from, to, refType, SourceType.USER_DEFINED, operandIndex);
			String operand = operandIndex == CodeUnit.MNEMONIC
					? "mnemonic"
					: "operand " + operandIndex;
			return "Created " + refType + " reference " + reference.getFromAddress() + " -> " +
				reference.getToAddress() + " (" + operand +
				(reference.isPrimary() ? ", primary" : "") + ")";
		});
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
			// Report the function the program ACTUALLY holds now, not what was requested. Ghidra
			// normalizes a supplied body (an address set ending mid-instruction, say), so the two
			// can differ — and echoing the request back as if it were the result is a lie the
			// caller cannot see. It cost a real investigation: a requested 464-byte body was
			// reported as 464 while the function was in fact 462, sending the reader after a
			// phantom bug. Note CreateFunctionCmd.getFunction() is null when it *recreated* an
			// existing function, so ask the program rather than the command.
			Function created = cmd.getFunction();
			if (created == null) {
				created = program.getFunctionManager().getFunctionAt(address);
			}
			if (created == null) {
				// Should not happen: applyTo() succeeded. Say so rather than inventing a body.
				return "Created function @ " + address + " (could not read it back — report this)";
			}
			long actual = created.getBody().getNumAddresses();
			String bodyNote = ", body " + actual + " bytes";
			if (functionBody != null && actual != functionBody.getNumAddresses()) {
				bodyNote += " (requested " + functionBody.getNumAddresses() +
					"; Ghidra normalized it to the flow-derived body)";
			}
			return "Created function @ " + address + " (" + created.getName() + ")" + bodyNote;
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
	 * An existing function is itself a namespace, so paths may descend into one — which is the
	 * whole point for decompiler overrides, whose namespace is rooted at the function
	 * ({@code <func>::override::jmp_<addr>}).
	 *
	 * <p>{@code SymbolTable.getNamespace(name, parent)} deliberately does not resolve functions
	 * (its javadoc: "but not a function"), because a function name may be duplicated within a
	 * parent. Using it here silently created a *second*, plain namespace beside the function and
	 * put the labels there, where nothing that reads overrides ever looks. {@link NamespaceUtils}
	 * matches on {@code SymbolType.isNamespace()}, which functions satisfy.
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
			List<Namespace> existing = NamespaceUtils.getNamespacesByName(program, namespace, part);
			namespace = existing.isEmpty()
					? symbolTable.createNameSpace(namespace, part, SourceType.USER_DEFINED)
					: existing.get(0);
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
