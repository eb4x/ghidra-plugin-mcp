package ebbex.ghidramcpserver.util;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.AbstractIntegerDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Undefined;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighLocal;
import ghidra.program.model.pcode.HighParam;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.HighVariable;
import ghidra.program.model.pcode.PcodeException;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.pcode.VarnodeAST;

/**
 * Shared resolution of a function's variables. Parameters and simple stack locals exist on the
 * database function directly; anything else (register locals, decompiler-synthesized names)
 * only exists as a decompiler {@link HighSymbol}, which costs a decompile to look up — so
 * callers try {@link #findDbVariable} first.
 *
 * <p>A decompiler name ({@code iVar7}) is not a stable handle: the decompiler renumbers its
 * temporaries after every edit. The address of the instruction that defines a variable is, so
 * {@link #findByPc} resolves one from that, and {@link #split} peels exactly the merge group
 * defined there — the GUI's "Split Out As New Variable".
 */
public final class Variables {

	private static final int DECOMPILE_TIMEOUT = 30;

	/** The decompiler's own naming: a type-prefixed counter, or the local_/param_/in_ forms. */
	private static final Pattern AUTO_NAME =
		Pattern.compile("^(?:[a-z]{1,3}Var\\d+|local_[0-9a-f]+|param_\\d+|in_[A-Za-z0-9_]+)$");

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
		HighFunction high = decompile(decompilers, program, function);
		if (high == null) {
			return null;
		}
		return high.getLocalSymbolMap().getNameToSymbolMap().get(name);
	}

	/**
	 * A decompiler variable picked by the varnode defined at one instruction. {@code pickNote}
	 * is empty, or says how the pick was defaulted when the caller gave no storage.
	 */
	public record HighTarget(HighFunction high, HighVariable variable, Varnode varnode,
			String pickNote) {

		public HighSymbol symbol() {
			return variable.getSymbol();
		}

		/**
		 * Where the variable's <em>other</em> merge groups are defined — the instances a split
		 * leaves behind, or that a whole-group edit carries along — as distinct, sorted pcs.
		 */
		public List<Address> otherPcs() {
			List<Address> pcs = new ArrayList<>();
			for (Varnode instance : variable.getInstances()) {
				Address at = instance.getPCAddress();
				if (instance.getMergeGroup() == varnode.getMergeGroup() || at == null ||
					at == Address.NO_ADDRESS || pcs.contains(at)) {
					continue;
				}
				pcs.add(at);
			}
			pcs.sort(null);
			return pcs;
		}

		/** How many of the variable's instances share the picked varnode's merge group. */
		public int groupSize() {
			int n = 0;
			for (Varnode instance : variable.getInstances()) {
				if (instance.getMergeGroup() == varnode.getMergeGroup()) {
					n++;
				}
			}
			return n;
		}

		public int instanceCount() {
			return variable.getInstances().length;
		}
	}

	/**
	 * The decompiler variable whose instance is <em>defined</em> by the instruction at
	 * {@code pc} ({@code dump_symbols} prints it as {@code pc=}). {@code storage}, when given,
	 * picks between several definitions at that instruction (a DX:AX call result is two), as a
	 * register name or whatever {@link #storageText} prints. Decompiles.
	 *
	 * @throws IllegalArgumentException if nothing is defined there, or more than one variable is
	 *             and {@code storage} does not single one out — the message lists them
	 */
	public static HighTarget findByPc(Decompilers decompilers, Program program, Function function,
			Address pc, String storage) {
		HighFunction high = decompile(decompilers, program, function);
		if (high == null) {
			throw new IllegalArgumentException("Could not decompile " + function.getName() +
				" to resolve the variable defined at " + pc);
		}
		// Keyed by "name @ storage", not by HighVariable: once a definition carries a locked
		// symbol the decompiler can hand back two HighVariables for it (the stored symbol's and
		// its own), and a pick that is ambiguous against itself is no pick.
		Map<String, HighTarget> candidates = new LinkedHashMap<>();
		List<String> named = new ArrayList<>();
		List<String> unnamed = new ArrayList<>();
		Iterator<VarnodeAST> varnodes = high.locRange();
		while (varnodes.hasNext()) {
			Varnode vn = varnodes.next();
			HighVariable owner = vn.getHigh();
			if (owner == null || !pc.equals(vn.getPCAddress())) {
				continue;
			}
			// Constants, globals and unmapped temporaries are written there too, but none of
			// them is a local the handle can name; listing them buried the one that is.
			if (!(owner instanceof HighLocal || owner instanceof HighParam)) {
				continue;
			}
			String text = storageText(high, program, vn);
			String key = owner.getName() + " @ " + text;
			boolean isUnnamed = owner.getName() == null || owner.getName().equals("UNNAMED");
			if (isUnnamed) {
				unnamed.add(key);
			}
			else if (!named.contains(key)) {
				named.add(key);
			}
			if (storage != null && !storageMatches(text, storage)) {
				continue;
			}
			// Nameless stack halves the call scribbles over are selectable by storage only;
			// without one, the named definitions are what the caller is choosing between.
			if (isUnnamed && storage == null && !named.isEmpty()) {
				continue;
			}
			candidates.putIfAbsent(key, new HighTarget(high, owner, vn, ""));
		}
		if (candidates.size() == 1) {
			return candidates.values().iterator().next();
		}
		// A call defines its result and, through INDIRECT ops, every frame slot it may
		// clobber. Pointed at the call with no storage, the caller means the result.
		if (storage == null && candidates.size() > 1) {
			List<HighTarget> results = candidates.values().stream()
					.filter(t -> isCallOutput(t.varnode()))
					.toList();
			if (results.size() == 1) {
				HighTarget result = results.get(0);
				return new HighTarget(result.high(), result.variable(), result.varnode(),
					" — the call's result, picked over " + (candidates.size() - 1) +
						" frame slot(s) the call may clobber; 'storage' picks one of those");
			}
		}
		List<String> listed = named.isEmpty() ? unnamed : named;
		if (candidates.isEmpty()) {
			throw new IllegalArgumentException("No decompiler variable is defined at " + pc +
				(storage == null ? "" : " in " + storage) + (listed.isEmpty()
						? " (no instruction there writes a local; decompile dump_symbols=true " +
							"prints each symbol's pc)"
						: "; defined there: " + String.join(", ", listed) +
							(unnamed.isEmpty() || named.isEmpty() ? ""
									: " (+" + unnamed.size() + " unnamed stack slot(s))")));
		}
		throw new IllegalArgumentException(candidates.size() + " variables are defined at " + pc +
			"; add 'storage' to pick one (spelled as listed, or DX:AX for a pair): " +
			String.join(", ", candidates.keySet()));
	}

	/** True when the varnode is what a CALL or CALLIND produces, not an INDIRECT side effect. */
	private static boolean isCallOutput(Varnode vn) {
		PcodeOp def = vn.getDef();
		return def != null &&
			(def.getOpcode() == PcodeOp.CALL || def.getOpcode() == PcodeOp.CALLIND);
	}

	/** "; other instances of iVar3 defined at 1000:0a12, 1000:0a40" (capped), or "". */
	public static String otherPcsNote(HighTarget target, String name, String verb) {
		List<Address> pcs = target.otherPcs();
		if (pcs.isEmpty()) {
			return "";
		}
		int cap = 8;
		List<String> shown = pcs.stream().limit(cap).map(Address::toString).toList();
		return "; " + verb + " " + pcs.size() + " other instance(s) of " + name + " defined at " +
			String.join(", ", shown) + (pcs.size() > cap ? ", …" : "");
	}

	/**
	 * Peel the picked varnode's merge group off its variable so it gets a symbol of its own —
	 * the original symbol stays with the group holding the representative. Returns the variable
	 * that now carries the picked varnode. Nothing is written until the symbol is committed.
	 */
	public static HighVariable split(HighTarget target) throws PcodeException {
		return target.high().splitOutMergeGroup(target.variable(), target.varnode());
	}

	/**
	 * The type a split-out variable is committed with when none is requested: the decompiler
	 * leaves an undefined type unlocked, so the peel would merge straight back; the GUI
	 * substitutes an unsigned integer of the same size, and so does this.
	 */
	public static DataType lockableType(Program program, DataType current) {
		if (Undefined.isUndefined(current)) {
			return AbstractIntegerDataType.getUnsignedDataType(current.getLength(),
				program.getDataTypeManager());
		}
		return current;
	}

	/** True for a decompiler-invented name: {@code iVar7}, {@code pcVar3}, {@code local_42}. */
	public static boolean isAutoName(String name) {
		return name != null && AUTO_NAME.matcher(name).matches();
	}

	/**
	 * The function's variables Ghidra would delete when a symbol with this storage and first
	 * use is committed: those with the <em>same first use</em> whose storage intersects it,
	 * other than {@code exclude} and the one with exactly that storage (which Ghidra reuses).
	 * Register locals are keyed by storage plus first use, so a DX:AX result at one call
	 * collides with the DX half defined by that same call and with nothing else in the
	 * function — the rule {@code VariableUtilities.checkVariableConflict} and
	 * {@code HighFunctionDBUtil.clearConflictingLocalVariables} both apply. Committing over
	 * them is silent, so a caller lists these first and asks before going on.
	 */
	public static List<Variable> intersecting(Function function, VariableStorage storage,
			Address pc, Variable exclude) {
		List<Variable> hits = new ArrayList<>();
		if (storage == null || !storage.isValid() || storage.isHashStorage()) {
			return hits;
		}
		int firstUse = pc == null ? 0 : (int) pc.subtract(function.getEntryPoint());
		for (Variable other : function.getAllVariables()) {
			if (other.equals(exclude) || other.getFirstUseOffset() != firstUse) {
				continue;
			}
			VariableStorage otherStorage = other.getVariableStorage();
			if (!otherStorage.intersects(storage) || otherStorage.equals(storage)) {
				continue;
			}
			hits.add(other);
		}
		return hits;
	}

	/** {@code name (type @ storage, first use addr)} for each, comma-separated. */
	public static String describe(Function function, List<Variable> variables) {
		List<String> parts = new ArrayList<>();
		for (Variable v : variables) {
			parts.add(v.getName() + " (" + v.getDataType().getName() + " @ " +
				v.getVariableStorage() + ", first use " + firstUse(function, v) + ")");
		}
		return String.join(", ", parts);
	}

	/** The address a variable's first-use offset denotes, or "entry" for offset 0. */
	public static String firstUse(Function function, Variable variable) {
		int offset = variable.getFirstUseOffset();
		if (offset == 0) {
			return "entry";
		}
		try {
			return function.getEntryPoint().add(offset).toString();
		}
		catch (RuntimeException e) {
			return "entry+0x" + Integer.toHexString(offset);
		}
	}

	/**
	 * Every variable of the function by symbol id, described, taken before a commit so that
	 * {@link #removedSince} can name what the commit deleted — a deleted symbol has no name left
	 * to print afterwards.
	 */
	public static Map<Long, String> snapshot(Function function) {
		Map<Long, String> byId = new LinkedHashMap<>();
		for (Variable v : function.getAllVariables()) {
			if (v.getSymbol() != null) {
				byId.put(v.getSymbol().getID(), v.getName() + " (" + v.getDataType().getName() +
					" @ " + v.getVariableStorage() + ", first use " + firstUse(function, v) + ")");
			}
		}
		return byId;
	}

	/** The described variables of {@code before} that the function no longer has. */
	public static List<String> removedSince(Function function, Map<Long, String> before) {
		Map<Long, String> after = snapshot(function);
		List<String> removed = new ArrayList<>();
		before.forEach((id, text) -> {
			if (!after.containsKey(id)) {
				removed.add(text);
			}
		});
		return removed;
	}

	/**
	 * A varnode's storage the way {@code dump_symbols} prints a symbol's: {@code AX:2},
	 * {@code DX:2,AX:2} for a joined pair (the decompiler's own address for it is an opaque
	 * {@code VARIABLE:...}), {@code Stack[-0x10]:2}.
	 */
	public static String storageText(HighFunction high, Program program, Varnode vn) {
		try {
			return high.buildStorage(vn).toString();
		}
		catch (Exception e) {
			return storageText(program, vn);
		}
	}

	/** {@code AX:2}, {@code Stack[-0x10]:2}, or {@code addr:size} for a plain varnode. */
	public static String storageText(Program program, Varnode vn) {
		Register register = program.getRegister(vn.getAddress(), vn.getSize());
		if (register != null) {
			return register.getName() + ":" + vn.getSize();
		}
		if (vn.getAddress().isStackAddress()) {
			long offset = vn.getAddress().getOffset();
			return "Stack[" + (offset < 0 ? "-0x" + Long.toHexString(-offset)
					: "0x" + Long.toHexString(offset)) + "]:" + vn.getSize();
		}
		return vn.getAddress() + ":" + vn.getSize();
	}

	/**
	 * Whether a caller's spelling names this storage: as printed ({@code DX:2,AX:2}), without
	 * the sizes ({@code DX,AX}), or as a register pair ({@code DX:AX}), case-insensitively.
	 */
	static boolean storageMatches(String text, String wanted) {
		return text.equalsIgnoreCase(wanted.trim()) ||
			normalizeStorage(text).equals(normalizeStorage(wanted));
	}

	/** {@code DX:2,AX:2}, {@code DX:AX}, {@code dx, ax} all become {@code dx,ax}. */
	static String normalizeStorage(String storage) {
		return storage.toLowerCase().replaceAll("\\s+", "").replaceAll(":\\d+", "")
				.replace(':', ',');
	}

	private static HighFunction decompile(Decompilers decompilers, Program program,
			Function function) {
		DecompileResults results = decompilers.decompile(program, function, DECOMPILE_TIMEOUT);
		return results != null ? results.getHighFunction() : null;
	}
}
