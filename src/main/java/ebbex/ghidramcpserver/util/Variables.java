package ebbex.ghidramcpserver.util;

import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighSymbol;

/**
 * Shared resolution of a function's variables by name. Parameters and simple stack
 * locals exist on the database function directly; anything else (register locals,
 * decompiler-synthesized names) only exists as a decompiler {@link HighSymbol}, which
 * costs a decompile to look up — so callers try {@link #findDbVariable} first.
 */
public final class Variables {

	private static final int DECOMPILE_TIMEOUT = 30;

	private Variables() {
	}

	/** The parameter or local variable named {@code name} on the database function, or null. */
	public static Variable findDbVariable(Function function, String name) {
		for (Parameter parameter : function.getParameters()) {
			if (parameter.getName().equals(name)) {
				return parameter;
			}
		}
		for (Variable local : function.getLocalVariables()) {
			if (local.getName().equals(name)) {
				return local;
			}
		}
		return null;
	}

	/** The decompiler symbol named {@code name} in the function, or null. Decompiles. */
	public static HighSymbol findHighSymbol(Decompilers decompilers, Program program,
			Function function, String name) {
		DecompileResults results = decompilers.decompile(program, function, DECOMPILE_TIMEOUT);
		HighFunction high = results != null ? results.getHighFunction() : null;
		if (high == null) {
			return null;
		}
		return high.getLocalSymbolMap().getNameToSymbolMap().get(name);
	}
}
