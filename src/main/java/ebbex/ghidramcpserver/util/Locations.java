package ebbex.ghidramcpserver.util;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
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

	private Locations() {
	}

	/** Parse a hex address string (with or without 0x / segment prefix). */
	public static Address parseAddress(Program program, String addressString) {
		Address address = program.getAddressFactory().getAddress(addressString);
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
		Address bareHex = program.getAddressFactory().getAddress(nameOrAddress);
		if (bareHex != null) {
			return bareHex;
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
		Address address = program.getAddressFactory().getAddress(addressString);
		if (address == null) {
			return null;
		}
		return program.getFunctionManager().getFunctionContaining(address);
	}
}
