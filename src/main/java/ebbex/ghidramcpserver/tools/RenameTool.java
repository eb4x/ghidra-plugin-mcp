package ebbex.ghidramcpserver.tools;

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
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.pcode.HighFunctionDBUtil;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.HighVariable;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolType;
import io.modelcontextprotocol.spec.McpSchema;

/** Rename any nameable thing: function, label, data, parameter, or local variable. */
public class RenameTool implements ProgramTool {

	private static final List<String> KINDS =
		List.of("function", "label", "data", "parameter", "local_variable");

	private final Decompilers decompilers;

	public RenameTool(Decompilers decompilers) {
		this.decompilers = decompilers;
	}

	@Override
	public String name() {
		return "rename";
	}

	@Override
	public String description() {
		return "Rename something. kind=function renames the function given by 'function'; " +
			"kind=label|data renames the symbol at 'address'. kind=parameter|local_variable " +
			"renames a variable inside the function given by 'function', identified by its " +
			"current 'variable_name' — or, for a decompiler variable, by 'pc', the address of the " +
			"instruction that defines it (decompile dump_symbols=true prints it as pc=); the " +
			"decompiler renumbers iVar7-style names after every edit, the pc does not move. With " +
			"'pc', only the merge group defined there is named: a variable the decompiler merged " +
			"from several roles is split and the new symbol type-locked (Ghidra's Split Out As New " +
			"Variable). reset=true (kind=function|label|data, no 'new_name') drops " +
			"the user name and returns to Ghidra's default: a function becomes FUN_<addr> or, " +
			"for a thunk, shows its target's name again; a label or data symbol is removed, and " +
			"the dynamic DAT_ label shows while something references the address.";
	}

	@Override
	public Map<String, Object> inputSchema() {
		return Map.of(
			"type", "object",
			"properties", Map.of(
				"kind", Schemas.enumProp("What to rename", KINDS),
				"new_name", Schemas.stringProp("The new name (not needed with reset=true)"),
				"reset", Schemas.boolProp("kind=function|label|data: return to Ghidra's default " +
					"name instead of giving a new one (default false)"),
				"function", Schemas.stringProp("Function name or an address inside it " +
					"(for kind=function|parameter|local_variable)"),
				"address", Schemas.stringProp("Address of the label/data (for kind=label|data)"),
				"variable_name", Schemas.stringProp(
					"Current variable name (for kind=parameter|local_variable)"),
				"pc", Schemas.stringProp("kind=local_variable: address of the instruction that " +
					"defines the variable, instead of 'variable_name'"),
				"storage", Schemas.stringProp("With 'pc': which definition at that instruction " +
					"when there are several (a register name such as DX, or Stack[-0x10])")),
			"required", List.of("kind"));
	}

	@Override
	public boolean isReadOnly() {
		return false;
	}

	@Override
	public McpSchema.CallToolResult execute(Map<String, Object> args, Program program) {
		String kind = Args.stringArg(args, "kind", null);
		String newName = Args.stringArg(args, "new_name", null);
		if (kind == null || !KINDS.contains(kind)) {
			return Results.error("kind must be one of " + KINDS);
		}
		boolean reset = Args.boolArg(args, "reset", false);
		if (reset && (kind.equals("parameter") || kind.equals("local_variable"))) {
			return Results.error("reset=true applies to kind=function|label|data; a variable " +
				"has no default name to return to");
		}
		if (!reset && (newName == null || newName.isBlank())) {
			return Results.error("new_name is required (or reset=true to return to the default)");
		}

		return switch (kind) {
			case "function" -> reset ? resetFunction(program, args)
					: renameFunction(program, args, newName);
			case "label", "data" -> reset ? resetSymbol(program, args)
					: renameSymbol(program, args, kind, newName);
			case "parameter", "local_variable" -> renameVariable(program, args, newName);
			default -> Results.error("unhandled kind " + kind);
		};
	}

	private McpSchema.CallToolResult renameFunction(Program program, Map<String, Object> args,
			String newName) {
		String ref = Args.stringArg(args, "function", null);
		if (ref == null) {
			return Results.error("'function' (a name or an address inside it) is required");
		}
		Function function = Locations.findFunction(program, ref);
		return Transactions.modify(program, "Rename function", () -> {
			String old = function.getName();
			// A FID pass (or a multi-match) can leave the wanted name behind as a SECONDARY
			// label at the entry; setName then fails with "A symbol named X already exists at
			// this address". The caller's intent is unambiguous — make X the function — so
			// absorb that label instead of bouncing the call back to clear it first.
			String absorbed = "";
			for (Symbol symbol : program.getSymbolTable().getSymbols(function.getEntryPoint())) {
				if (!symbol.isPrimary() && symbol.getName().equals(newName)) {
					absorbed = " (absorbed the secondary " + symbol.getSource() + " label '" +
						newName + "' that was already at the entry)";
					symbol.delete();
					break;
				}
			}
			function.setName(newName, SourceType.USER_DEFINED);
			return "Renamed function " + old + " -> " + newName + " @ " +
				function.getEntryPoint() + absorbed;
		});
	}

	/**
	 * Back to the default name: Ghidra does this with a DEFAULT-source rename (the stored name
	 * becomes empty and the symbol prints FUN_addr, or the target's name for a thunk), not by
	 * deleting the symbol — deleting a function symbol removes the function.
	 */
	private McpSchema.CallToolResult resetFunction(Program program, Map<String, Object> args) {
		String ref = Args.stringArg(args, "function", null);
		if (ref == null) {
			return Results.error("'function' (a name or an address inside it) is required");
		}
		Function function = Locations.findFunction(program, ref);
		if (function.getSymbol().getSource() == SourceType.DEFAULT) {
			return Results.ok(function.getName() + " @ " + function.getEntryPoint() +
				" already has its default name");
		}
		return Transactions.modify(program, "Reset function name", () -> {
			String old = function.getName();
			function.getSymbol().setName(null, SourceType.DEFAULT);
			return "Reset function " + old + " @ " + function.getEntryPoint() +
				" to its default name " + function.getName() +
				(function.isThunk() ? " (a default-named thunk follows its target's name)" : "");
		});
	}

	/**
	 * A label has no stored default: removing the user symbol is the reset, and the dynamic
	 * DAT_/LAB_ name reappears on its own while something references the address.
	 */
	private McpSchema.CallToolResult resetSymbol(Program program, Map<String, Object> args) {
		String addressArg = Args.stringArg(args, "address", null);
		if (addressArg == null) {
			return Results.error("'address' is required for kind=label|data");
		}
		Address address = Locations.parseAddress(program, addressArg);
		Symbol symbol = program.getSymbolTable().getPrimarySymbol(address);
		if (symbol == null || symbol.getSource() == SourceType.DEFAULT) {
			return Results.ok("No user symbol at " + address + " to reset" +
				(symbol == null ? "" : " (" + symbol.getName() + " is already the default)"));
		}
		if (symbol.getSymbolType() == SymbolType.FUNCTION) {
			return resetFunction(program, Map.of("function", address.toString()));
		}
		return Transactions.modify(program, "Reset label", () -> {
			String old = symbol.getName();
			symbol.delete();
			Symbol now = program.getSymbolTable().getPrimarySymbol(address);
			return "Removed label " + old + " @ " + address + (now == null
					? " (nothing references the address, so no default label shows)"
					: "; it now shows as " + now.getName());
		});
	}

	private McpSchema.CallToolResult renameSymbol(Program program, Map<String, Object> args,
			String kind, String newName) {
		String addressArg = Args.stringArg(args, "address", null);
		if (addressArg == null) {
			return Results.error("'address' is required for kind=label|data");
		}
		Address address = Locations.parseAddress(program, addressArg);
		Symbol symbol = program.getSymbolTable().getPrimarySymbol(address);
		if (symbol == null && kind.equals("data") &&
			program.getListing().getDefinedDataAt(address) != null) {
			// Ghidra's default DAT_/PTR_ARRAY_ labels are dynamic: they exist only where
			// something references the address, not because data is defined there. So whether
			// "rename the data at X" finds a symbol looked like it depended on the type applied
			// a moment earlier; it depended on the references. Naming defined data that has no
			// symbol yet is what the caller meant — make the label.
			return Transactions.modify(program, "Name data", () -> {
				program.getSymbolTable().createLabel(address, newName, SourceType.USER_DEFINED);
				return "Named the data at " + address + " " + newName +
					" (it had no symbol: nothing references it, so no default label existed)";
			});
		}
		if (symbol == null) {
			return Results.error("No symbol at " + address + " to rename — this address has no " +
				"symbol yet (e.g. a bare byte in a data/BSS block). Use create kind=label to make " +
				"a new label at an address.");
		}
		return Transactions.modify(program, "Rename symbol", () -> {
			String old = symbol.getName();
			symbol.setName(newName, SourceType.USER_DEFINED);
			return "Renamed " + old + " -> " + newName + " @ " + address;
		});
	}

	private McpSchema.CallToolResult renameVariable(Program program, Map<String, Object> args,
			String newName) {
		String functionRef = Args.stringArg(args, "function", null);
		String oldName = Args.stringArg(args, "variable_name", null);
		String pcArg = Args.stringArg(args, "pc", null);
		if (functionRef == null || (oldName == null && pcArg == null)) {
			return Results.error("'function' and 'variable_name' (or 'pc') are required for " +
				"variable renames");
		}
		Function function = Locations.findFunction(program, functionRef);
		if (pcArg != null) {
			return renameByPc(program, function, Locations.parseAddress(program, pcArg),
				Args.stringArg(args, "storage", null), newName);
		}

		// Parameters and simple stack locals exist on the database function directly.
		Variable dbVariable = Variables.findDbVariable(function, oldName);
		if (dbVariable != null) {
			return Transactions.modify(program, "Rename variable", () -> {
				dbVariable.setName(newName, SourceType.USER_DEFINED);
				return "Renamed variable " + oldName + " -> " + newName + " in " +
					function.getName();
			});
		}

		// Otherwise resolve a decompiler HighSymbol (off the EDT), then apply in a transaction.
		HighSymbol highSymbol = Variables.findHighSymbol(decompilers, program, function, oldName);
		if (highSymbol == null) {
			return Results.error("No parameter or local variable named '" + oldName + "' in " +
				function.getName() + " (the decompiler renumbers its temporaries after every " +
				"edit; rename by 'pc', the defining instruction, which does not move)");
		}
		return Transactions.modify(program, "Rename variable", () -> {
			refuseIfOverlapping(function, highSymbol.getStorage(), highSymbol.getPCAddress(), null);
			var before = Variables.snapshot(function);
			HighFunctionDBUtil.updateDBVariable(highSymbol, newName, null,
				SourceType.USER_DEFINED);
			return "Renamed variable " + oldName + " -> " + newName + " in " + function.getName() +
				removedNote(function, before);
		});
	}

	/**
	 * Name the variable defined at one instruction. If that definition is one merge group of a
	 * larger speculative merge, only its group is split out and named — the GUI's "Split Out As
	 * New Variable" — and the new symbol is type-locked (an undefined type becomes the unsigned
	 * integer of its size), because an unlocked peel merges straight back.
	 */
	private McpSchema.CallToolResult renameByPc(Program program, Function function, Address pc,
			String storage, String newName) {
		Variables.HighTarget target = Variables.findByPc(decompilers, program, function, pc, storage);
		return Transactions.modify(program, "Rename variable", () -> {
			String oldName = target.variable().getName();
			int group = target.groupSize();
			int all = target.instanceCount();
			HighVariable peeled = Variables.split(target);
			HighSymbol symbol = peeled.getSymbol();
			DataType type = Variables.lockableType(program, symbol.getDataType());
			refuseIfOverlapping(function, symbol.getStorage(), symbol.getPCAddress(), null);
			var before = Variables.snapshot(function);
			HighFunctionDBUtil.updateDBVariable(symbol, newName, type, SourceType.USER_DEFINED);
			String where = Variables.storageText(target.high(), program, target.varnode()) +
				" defined at " + pc;
			String split = group < all
					? "split " + group + " of " + all + " instances of " + oldName +
						" out as their own variable"
					: "all " + all + " instances of " + oldName;
			return "Named " + newName + ": " + where + " (" + split + "; type-locked as " +
				type.getName() + ")" + removedNote(function, before);
		});
	}

	/**
	 * Ghidra removes any local whose storage a newly committed symbol intersects, without a
	 * word (a type lock on a DX:AX call result took the DX:2 symbol next to it). Name them and
	 * stop instead; set_data_type replace_overlapping=true is the deliberate way through.
	 */
	private static void refuseIfOverlapping(Function function, VariableStorage storage, Address pc,
			Variable exclude) throws Exception {
		List<Variable> hits = Variables.intersecting(function, storage, pc, exclude);
		if (!hits.isEmpty()) {
			throw new Exception("committing a symbol at " + storage + " would remove " +
				hits.size() + " existing variable(s) whose storage it overlaps: " +
				Variables.describe(function, hits) + ". Clear them first (clear " +
				"kind=local_variable), or use set_data_type replace_overlapping=true.");
		}
	}

	private static String removedNote(Function function, Map<Long, String> before) {
		List<String> removed = Variables.removedSince(function, before);
		return removed.isEmpty() ? ""
				: "\nRemoved by Ghidra as overlapping: " + String.join(", ", removed);
	}
}
