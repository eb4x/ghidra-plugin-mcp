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
import ghidra.program.model.mem.MemoryAccessException;
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
			"functions_at_labels", "functions_from_table");

	/** How many created/skipped names the functions_at_labels summary spells out. */
	private static final int MAX_NAMED = 50;

	/** Sanity cap for functions_from_table — a count above this is a wrong argument. */
	private static final int MAX_TABLE_ENTRIES = 4096;

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
			"(optional 'name'), disassembling at the address first if nothing is there — as the " +
			"GUI does — and saying HUSK if the body still comes out one byte; kind=label adds a " +
			"label ('name' required); kind=bookmark adds a " +
			"note bookmark (optional 'category', 'comment' is the text); kind=instructions " +
			"disassembles from the address (like pressing 'D'), e.g. after clear. For kind=function " +
			"an optional 'end_address' asks for that inclusive body range (works on an existing " +
			"function too), but Ghidra normalises the body to what flow reaches and the result " +
			"reports the size it actually kept — so it cannot SHRINK an existing function whose old " +
			"body holds undecoded bytes: clear kind=function first, then create. A function created " +
			"on a JMP is a thunk to the jump target (and Ghidra makes the target a function too); " +
			"the result says so — if the real entry is after the jump, create there instead. " +
			"omit it to auto-compute from flow. For kind=label an optional " +
			"'namespace' ('::'-separated path, e.g. \"main::override\") puts the label in that " +
			"namespace, creating missing levels. kind=reference adds a memory reference from " +
			"'address' to 'to_address' with 'ref_type' (e.g. computed_jump for hand-applied " +
			"jump-table targets); optional 'operand_index' ties it to an operand (default: the " +
			"mnemonic). kind=functions_at_labels takes no address: it creates a function at every " +
			"user/imported-named label that sits in executable memory on no defined data and " +
			"starts no function yet (the OMF PUBDEF case — entry points that import as plain " +
			"labels); the label becomes the function's name. kind=functions_from_table walks a " +
			"pointer table at 'address': 'count' entries of 'entry_size' bytes (default: the " +
			"program's pointer size), one every 'stride' bytes (default entry_size; set it to the " +
			"record size for tables of <pointer, extra fields> records, with 'address' on the " +
			"first pointer), endianness from the language unless 'big_endian' overrides. Each " +
			"entry gets a reference ('ref_type', default computed_call) from its slot to the " +
			"target plus a function created there — the USB-dispatch / handler-table case. " +
			"Every target becomes a FUNCTION, so this is for handler tables; switch-case " +
			"targets are blocks inside one function (Keil C51 ?C?xCASE tables are handled by the " +
			"Keil8051 extension's analyzer instead). Entries resolving outside memory are listed, " +
			"not fatal ('count' is never guessed from a terminator).";
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
			"Inclusive end address requested for the function body (for kind=function); Ghidra " +
			"renormalises it to flow, and the result says what it kept"));
		properties.put("namespace", Schemas.stringProp(
			"'::'-separated namespace path for the label (for kind=label)"));
		properties.put("to_address",
			Schemas.stringProp("Reference target address (for kind=reference)"));
		properties.put("ref_type", Schemas.enumProp(
			"Reference type (for kind=reference|functions_from_table; " +
			"functions_from_table defaults to computed_call)", List.copyOf(REF_TYPES.keySet())));
		properties.put("operand_index", Schemas.intProp(
			"Operand the reference hangs off, 0-based (for kind=reference; default: mnemonic)"));
		properties.put("count", Schemas.intProp(
			"Number of table entries to walk (for kind=functions_from_table; required — never " +
			"guessed from a terminator)"));
		properties.put("entry_size", Schemas.intProp(
			"Pointer width in bytes, 2-8 (for kind=functions_from_table; default: the program's " +
			"pointer size)"));
		properties.put("stride", Schemas.intProp(
			"Bytes between consecutive pointers (for kind=functions_from_table; default: " +
			"entry_size — set it to the record size when each pointer is followed by other fields)"));
		properties.put("big_endian", Schemas.boolProp(
			"Pointer byte order (for kind=functions_from_table; default: the language's " +
			"endianness)"));
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
			case "functions_from_table" -> createFunctionsFromTable(program, address, args);
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
			List<String> husks = new ArrayList<>();
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
				try {
					ensureInstructionAt(program, address);
				}
				catch (IllegalArgumentException e) {
					failed.add(symbol.getName() + " @ " + address + ": " + e.getMessage());
					continue;
				}
				CreateFunctionCmd cmd =
					new CreateFunctionCmd(null, address, null, SourceType.USER_DEFINED);
				if (cmd.applyTo(program, TaskMonitor.DUMMY)) {
					Function function = program.getFunctionManager().getFunctionAt(address);
					String name = (function != null ? function.getName() : symbol.getName()) +
						" @ " + address;
					if (function != null && !huskNote(program, function).isEmpty()) {
						husks.add(name);
					}
					else {
						created.add(name);
					}
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
					.append(husks.isEmpty() ? "" : ", " + husks.size() + " came out as 1-byte husks")
					.append(failed.isEmpty() ? "." : ", " + failed.size() + " failed.");
			appendNames(sb, "Created", created);
			appendNames(sb, "HUSKS (1-byte body, bytes did not disassemble)", husks);
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

	/**
	 * Walk a table of code pointers, wiring a reference from each slot and creating a
	 * function at each target — the repetitive by-hand part of resolving dispatch tables
	 * (USB request handler tables, interrupt/command dispatch). The
	 * count is always explicit: guessing a terminator would silently walk past a table
	 * whose 0 entry is a valid address on some other target.
	 */
	private McpSchema.CallToolResult createFunctionsFromTable(Program program, Address table,
			Map<String, Object> args) {
		int count = Args.intArg(args, "count", 0);
		if (count < 1 || count > MAX_TABLE_ENTRIES) {
			return Results.error("count (1-" + MAX_TABLE_ENTRIES + ") is required for " +
				"kind=functions_from_table — the number of table entries, never guessed");
		}
		int entrySize = Args.intArg(args, "entry_size", program.getDefaultPointerSize());
		if (entrySize < 2 || entrySize > 8) {
			return Results.error("entry_size must be 2-8 bytes");
		}
		int stride = Args.intArg(args, "stride", entrySize);
		if (stride < entrySize) {
			return Results.error("stride must be at least entry_size (" + entrySize + ")");
		}
		boolean bigEndian =
			Args.boolArg(args, "big_endian", program.getLanguage().isBigEndian());
		String refTypeArg = Args.stringArg(args, "ref_type", "computed_call");
		RefType refType = REF_TYPES.get(refTypeArg);
		if (refType == null) {
			return Results.error("ref_type must be one of " + REF_TYPES.keySet());
		}

		return Transactions.modify(program, "Create functions from pointer table", () -> {
			List<String> created = new ArrayList<>();
			List<String> husks = new ArrayList<>();
			List<String> invalid = new ArrayList<>();
			List<String> failed = new ArrayList<>();
			int existing = 0;
			for (int i = 0; i < count; i++) {
				Address slot = table.add((long) i * stride);
				long value;
				try {
					value = readPointer(program, slot, entrySize, bigEndian);
				}
				catch (MemoryAccessException e) {
					// A slot past the block's end; the rest of the table is out with it, but
					// the entries already walked stand — report rather than abort.
					invalid.add(slot + ": no bytes to read (" + e.getMessage() + ")");
					continue;
				}
				Address target;
				try {
					target = slot.getNewAddress(value);
				}
				catch (RuntimeException e) {
					// Beyond the address space itself (garbage read as a wide pointer).
					invalid.add(slot + " -> 0x" + Long.toHexString(value) + " (outside memory)");
					continue;
				}
				if (!program.getMemory().contains(target)) {
					invalid.add(slot + " -> 0x" + Long.toHexString(value) + " (outside memory)");
					continue;
				}
				program.getReferenceManager().addMemoryReference(slot, target, refType,
					SourceType.USER_DEFINED, CodeUnit.MNEMONIC);
				if (program.getFunctionManager().getFunctionAt(target) != null) {
					existing++;
					continue;
				}
				try {
					ensureInstructionAt(program, target);
				}
				catch (IllegalArgumentException e) {
					failed.add(slot + " -> " + target + ": " + e.getMessage());
					continue;
				}
				CreateFunctionCmd cmd =
					new CreateFunctionCmd(null, target, null, SourceType.USER_DEFINED);
				if (!cmd.applyTo(program, TaskMonitor.DUMMY)) {
					failed.add(slot + " -> " + target + ": " + cmd.getStatusMsg());
					continue;
				}
				Function function = program.getFunctionManager().getFunctionAt(target);
				String note = function != null ? function.getName() + " @ " + target
						: "@ " + target;
				if (function != null && !huskNote(program, function).isEmpty()) {
					husks.add(note);
				}
				else {
					created.add(note);
				}
			}
			StringBuilder sb = new StringBuilder();
			sb.append("Walked ").append(count).append(" table entr").append(count == 1 ? "y" : "ies")
					.append(" @ ").append(table).append(" (").append(entrySize)
					.append("-byte pointers every ").append(stride).append(" bytes, ")
					.append(bigEndian ? "big" : "little").append("-endian, ").append(refType)
					.append(" refs): ").append(created.size()).append(" function(s) created, ")
					.append(existing).append(" already existed")
					.append(husks.isEmpty() ? "" : ", " + husks.size() + " came out as 1-byte husks")
					.append(invalid.isEmpty() ? "" : ", " + invalid.size() + " outside memory")
					.append(failed.isEmpty() ? "." : ", " + failed.size() + " failed.");
			appendNames(sb, "Created", created);
			appendNames(sb, "HUSKS (1-byte body, bytes did not disassemble)", husks);
			appendNames(sb, "Outside memory (no reference made)", invalid);
			appendNames(sb, "Failed", failed);
			return sb.toString();
		});
	}

	/** Assemble an unsigned pointer from raw table bytes; width and byte order are the caller's. */
	private static long readPointer(Program program, Address slot, int entrySize,
			boolean bigEndian) throws MemoryAccessException {
		byte[] raw = new byte[entrySize];
		program.getMemory().getBytes(slot, raw);
		long value = 0;
		for (int i = 0; i < entrySize; i++) {
			int b = raw[bigEndian ? i : entrySize - 1 - i] & 0xff;
			value = (value << 8) | b;
		}
		return value;
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
			int functionsBefore = program.getFunctionManager().getFunctionCount();
			String prelude = ensureInstructionAt(program, address);
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
			return "Created function @ " + address + " (" + created.getName() + ")" + bodyNote +
				prelude + huskNote(program, created) +
				thunkNote(program, created, functionsBefore);
		});
	}

	/**
	 * A function whose first instruction is a JMP becomes a Ghidra thunk, and Ghidra creates
	 * the jump target as a function of its own — two symbols the caller did not ask for, and
	 * the wrong two when the JMP is a 3-byte stub in front of the real entry. Say so.
	 */
	private static String thunkNote(Program program, Function created, int functionsBefore) {
		StringBuilder sb = new StringBuilder();
		if (created.isThunk()) {
			Function target = created.getThunkedFunction(false);
			sb.append(" — THUNK to ").append(target != null ? target.getName() : "?")
					.append(target != null ? " @ " + target.getEntryPoint() : "")
					.append(" (the entry is a JMP; if the real function starts after it, " +
						"clear kind=function here and create there)");
		}
		int extra = program.getFunctionManager().getFunctionCount() - functionsBefore - 1;
		if (extra > 0) {
			sb.append(" — Ghidra also created ").append(extra).append(" other function(s)")
					.append(created.isThunk() ? " (the thunk target)" : " (call/flow targets)");
		}
		return sb.toString();
	}

	/**
	 * {@link CreateFunctionCmd} never disassembles: on bytes nothing has decoded yet it
	 * takes the one undefined code unit at the entry as the whole body — a 1-byte husk, and
	 * a silent one. The GUI's Create Function action disassembles first, so do the same.
	 * Returns a note for the result, "" when an instruction was already there.
	 */
	private static String ensureInstructionAt(Program program, Address address) {
		if (program.getListing().getInstructionAt(address) != null) {
			return "";
		}
		if (program.getListing().getDefinedDataContaining(address) != null) {
			throw new IllegalArgumentException("Defined data at " + address +
				" — clear it first (clear kind=code) if this really is code");
		}
		DisassembleCommand disassemble = new DisassembleCommand(address, null, true);
		if (!disassemble.applyTo(program, TaskMonitor.DUMMY) ||
			program.getListing().getInstructionAt(address) == null) {
			throw new IllegalArgumentException("No instruction at " + address +
				" and the bytes there do not disassemble" +
				(disassemble.getStatusMsg() != null ? ": " + disassemble.getStatusMsg() : ""));
		}
		long bytes = disassemble.getDisassembledAddressSet() != null
				? disassemble.getDisassembledAddressSet().getNumAddresses()
				: 0;
		return "; disassembled " + bytes + " bytes first (nothing was decoded at the entry)";
	}

	/** A one-byte body with no instruction under it is a husk, not a function — say so. */
	private static String huskNote(Program program, Function function) {
		if (function.getBody().getNumAddresses() > 1 ||
			program.getListing().getInstructionAt(function.getEntryPoint()) != null) {
			return "";
		}
		return " — HUSK: 1-byte body over an undefined byte; the bytes did not disassemble";
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
