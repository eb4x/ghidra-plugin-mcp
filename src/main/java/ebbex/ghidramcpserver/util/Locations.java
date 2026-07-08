package ebbex.ghidramcpserver.util;

import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import ghidra.app.util.NamespaceUtils;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.SegmentedAddress;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolType;

/**
 * Shared, stateless helpers for resolving addresses, functions, and locations
 * within a {@link Program}. The program itself is supplied per call (resolved by
 * project path in {@link ProjectContext}); there is no notion of a "current"
 * program.
 *
 * <p>Name-or-address strings resolve in a fixed order everywhere: a string that is
 * syntactically an address ({@code seg:off}, {@code 0x}-prefixed, or
 * overlay-qualified) resolves as an address first; otherwise the symbol table is
 * consulted by name (indexed); a bare-hex string is tried as an address last.
 */
public final class Locations {

	/**
	 * A decompiler-synthesized global name for an unnamed memory location: a short type
	 * prefix, the literal {@code Ram}, then the location's <em>flat/linear</em> address
	 * (e.g. {@code bRam00035e3e}, {@code uRam00001234}). These are display names, not real
	 * symbols, so a name copy-pasted out of a decompile is otherwise unresolvable; group 1
	 * is the flat hex, which the address factory maps back to a real (segmented) address.
	 */
	private static final Pattern RAM_GLOBAL =
		Pattern.compile("(?i)^[a-z]{0,3}ram([0-9a-f]{4,8})$");

	private Locations() {
	}

	/** Parse a hex address string (with or without 0x / segment prefix). */
	public static Address parseAddress(Program program, String addressString) {
		Address address = toAddress(program, addressString);
		if (address == null) {
			throw new IllegalArgumentException("Invalid address: " + addressString);
		}
		return address;
	}

	/**
	 * Resolve a function by name or by an address inside it (in the shared
	 * name-or-address resolution order).
	 */
	public static Function findFunction(Program program, String nameOrAddress) {
		if (isAddressSyntax(nameOrAddress)) {
			Function byAddress = functionContaining(program, nameOrAddress);
			if (byAddress != null) {
				return byAddress;
			}
		}
		SymbolIterator symbols = program.getSymbolTable().getSymbols(nameOrAddress);
		while (symbols.hasNext()) {
			Symbol symbol = symbols.next();
			if (symbol.getSymbolType() == SymbolType.FUNCTION) {
				return program.getFunctionManager().getFunctionAt(symbol.getAddress());
			}
		}
		Function byBareHex = functionContaining(program, nameOrAddress);
		if (byBareHex != null) {
			return byBareHex;
		}
		Address namespaced = namespaceSymbol(program, nameOrAddress);
		if (namespaced != null) {
			Function containing =
				program.getFunctionManager().getFunctionContaining(namespaced);
			if (containing != null) {
				return containing;
			}
		}
		throw new IllegalArgumentException("No function named or containing address '" +
			nameOrAddress + "'");
	}

	/** Resolve a location by address or symbol name (shared resolution order). */
	public static Address findLocation(Program program, String nameOrAddress) {
		if (isAddressSyntax(nameOrAddress)) {
			Address address = program.getAddressFactory().getAddress(nameOrAddress);
			if (address != null) {
				return address;
			}
		}
		SymbolIterator symbols = program.getSymbolTable().getSymbols(nameOrAddress);
		if (symbols.hasNext()) {
			return symbols.next().getAddress();
		}
		// Bare hex, or a decompiler 'Ram' global name copy-pasted from a decompile.
		Address bareHex = toAddress(program, nameOrAddress);
		if (bareHex != null) {
			return bareHex;
		}
		// A namespace-qualified name like 'switchD_1000:2c03::caseD_6' the decompiler prints.
		Address namespaced = namespaceSymbol(program, nameOrAddress);
		if (namespaced != null) {
			return namespaced;
		}
		throw new IllegalArgumentException("No symbol or address '" + nameOrAddress + "'");
	}

	/**
	 * True if the string can only be meant as an address: {@code 1000:0234},
	 * {@code 0x2f0b}, or an overlay/space-qualified {@code BLOCK::0000} form.
	 * (A bare hex string like {@code 287c} is ambiguous — it could equally be a
	 * symbol name — so it is tried as an address only after the symbol lookup.)
	 */
	private static boolean isAddressSyntax(String s) {
		return s.matches("(?i)0x[0-9a-f]+") ||
			s.matches("(?i)[0-9a-f]+:[0-9a-f]+") ||
			s.contains("::");
	}

	private static Function functionContaining(Program program, String addressString) {
		Address address = toAddress(program, addressString);
		if (address == null) {
			return null;
		}
		return program.getFunctionManager().getFunctionContaining(address);
	}

	/**
	 * The address of a namespace-qualified symbol path like {@code switchD_1000:2c03::caseD_6}
	 * (the form the decompiler prints for switch-case labels), resolved through
	 * {@link NamespaceUtils#getSymbols}. Returns null when the string has no {@code ::} path or
	 * no such symbol exists. First match wins.
	 */
	private static Address namespaceSymbol(Program program, String name) {
		if (!name.contains("::")) {
			return null;
		}
		List<Symbol> symbols = NamespaceUtils.getSymbols(name, program);
		return symbols.isEmpty() ? null : symbols.get(0).getAddress();
	}

	/**
	 * The address for a string via the address factory, or {@code null}. Falls back to the
	 * decompiler's {@code <prefix>Ram<flat-hex>} global naming (see {@link #RAM_GLOBAL}) so a
	 * name copied straight out of a decompile resolves to the same physical byte the factory
	 * would give for that flat address.
	 */
	private static Address toAddress(Program program, String s) {
		Address address = program.getAddressFactory().getAddress(s);
		if (address != null) {
			return address;
		}
		Matcher matcher = RAM_GLOBAL.matcher(s);
		if (matcher.matches()) {
			Address flat = program.getAddressFactory().getAddress("0x" + matcher.group(1));
			return flat == null ? null : inContainingSegment(program, flat);
		}
		return null;
	}

	/**
	 * Re-express a flat-derived segmented address using the base segment of the memory block
	 * that contains it (DGROUP/DS, e.g. {@code 2b5a}, for data globals) rather than the address
	 * factory's canonical segment, so it echoes as the {@code seg:off} a caller sees in
	 * disassembly. Same physical byte either way. Falls back to the input when it is not
	 * segmented or not inside a block.
	 */
	private static Address inContainingSegment(Program program, Address flat) {
		if (!(flat instanceof SegmentedAddress segmented)) {
			return flat;
		}
		MemoryBlock block = program.getMemory().getBlock(flat);
		if (block != null && block.getStart() instanceof SegmentedAddress blockStart) {
			// normalize() returns the address unchanged if the offset does not fit the segment.
			return segmented.normalize(blockStart.getSegment());
		}
		return flat;
	}
}
