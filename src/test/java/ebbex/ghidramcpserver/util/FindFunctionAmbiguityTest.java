package ebbex.ghidramcpserver.util;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import org.junit.Test;

import ebbex.ghidramcpserver.RealModeProgramTest;
import ghidra.program.model.data.VoidDataType;

/**
 * A name two functions share (an overlay gate renamed after the body it jumps to) must be
 * refused with both candidates, not resolved to whichever the symbol table yields first.
 */
public class FindFunctionAmbiguityTest extends RealModeProgramTest {

	@Test
	public void uniqueNameResolves() throws Exception {
		builder.createEmptyFunction("madspack_read", "1000:0300", 0x10, VoidDataType.dataType);
		assertEquals("1000:0300",
			Locations.findFunction(program, "madspack_read").getEntryPoint().toString());
	}

	@Test
	public void sharedNameIsRefusedWithBothCandidates() throws Exception {
		builder.createEmptyFunction("madspack_read", "1000:0300", 0x10, VoidDataType.dataType);
		builder.createEmptyFunction("madspack_read", "gates", "1000:0400", 0x10,
			VoidDataType.dataType);
		try {
			Locations.findFunction(program, "madspack_read");
			fail("expected the shared name to be refused");
		}
		catch (IllegalArgumentException e) {
			String message = e.getMessage();
			assertTrue(message, message.contains("names 2 functions"));
			assertTrue(message, message.contains("1000:0300"));
			assertTrue(message, message.contains("gates::madspack_read @ 1000:0400"));
		}
		try {
			Locations.findLocation(program, "madspack_read");
			fail("expected the shared name to be refused as a location too");
		}
		catch (IllegalArgumentException e) {
			assertTrue(e.getMessage(), e.getMessage().contains("names 2 locations"));
		}
	}
}
