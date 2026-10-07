package ebbex.ghidramcpserver.util;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

import ebbex.ghidramcpserver.RealModeProgramTest;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.listing.Function;

/** Name-or-address resolution on segmented addresses: the operand grammar every tool shares. */
public class LocationsTest extends RealModeProgramTest {

	@Test
	public void functionByNameAndByContainedAddress() throws Exception {
		Function f = builder.createEmptyFunction("entry", "1000:0010", 0x20, VoidDataType.dataType);
		assertEquals(f, Locations.findFunction(program, "entry"));
		assertEquals(f, Locations.findFunction(program, "1000:0010"));
		assertEquals(f, Locations.findFunction(program, "1000:0025"));
	}

	@Test(expected = IllegalArgumentException.class)
	public void unknownFunctionIsAnError() {
		Locations.findFunction(program, "nothing_here");
	}

	@Test
	public void locationByLabelAndByAddress() throws Exception {
		builder.createLabel("1000:0040", "table");
		assertEquals(program.getAddressFactory().getAddress("1000:0040"),
			Locations.findLocation(program, "table"));
		assertEquals(program.getAddressFactory().getAddress("1000:0044"),
			Locations.findLocation(program, "1000:0044"));
	}

	@Test
	public void parseAddressIsStrict() {
		assertEquals(program.getAddressFactory().getAddress("1000:0008"),
			Locations.parseAddress(program, "1000:0008"));
		try {
			Locations.parseAddress(program, "table");
			throw new AssertionError("a symbol name is not an address");
		}
		catch (IllegalArgumentException expected) {
			assertTrue(expected.getMessage().contains("table"));
		}
	}

	@Test
	public void addressSyntaxIsRecognised() {
		assertTrue(Locations.isAddressSyntax("1000:0008"));
		assertTrue(Locations.isAddressSyntax("OVERLAY_72::02d000"));
		assertFalse(Locations.isAddressSyntax("sprite_series_load"));
	}
}
