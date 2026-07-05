package ebbex.ghidramcpserver.util;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;

/**
 * Shared, stateless helpers for resolving addresses, functions, and symbols
 * within a {@link Program}. The program itself is supplied per call (resolved by
 * project path in {@link ProjectContext}); there is no notion of a "current"
 * program.
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
	 * Resolve a function by name or entry-point address. Names are matched
	 * against all functions; addresses may point anywhere inside the function.
	 */
	public static Function findFunction(Program program, String nameOrAddress) {
		for (Function f : program.getFunctionManager().getFunctions(true)) {
			if (f.getName().equals(nameOrAddress)) {
				return f;
			}
		}
		// not a name - try as address (entry point or containing)
		try {
			Address address = parseAddress(program, nameOrAddress);
			Function f = program.getFunctionManager().getFunctionContaining(address);
			if (f != null) {
				return f;
			}
		}
		catch (IllegalArgumentException e) {
			// fall through to error below
		}
		throw new IllegalArgumentException("No function named or containing address '" +
			nameOrAddress + "'");
	}

	/** Resolve a location by symbol name or address string. */
	public static Address findLocation(Program program, String nameOrAddress) {
		Address address = program.getAddressFactory().getAddress(nameOrAddress);
		if (address != null) {
			return address;
		}
		SymbolIterator symbols = program.getSymbolTable().getSymbolIterator(nameOrAddress, true);
		if (symbols.hasNext()) {
			Symbol symbol = symbols.next();
			return symbol.getAddress();
		}
		throw new IllegalArgumentException("No symbol or address '" + nameOrAddress + "'");
	}
}
