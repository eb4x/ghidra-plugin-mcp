package ebbex.ghidramcpserver.tools;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

import org.junit.Test;

/** Struct offsets are taken as decimal or 0x-hex; anything else is "not an offset". */
public class ManageTypesOffsetTest {

	@Test
	public void decimalAndHex() {
		assertEquals(Integer.valueOf(26), ManageTypesTool.parseOffset("26"));
		assertEquals(Integer.valueOf(0x1a), ManageTypesTool.parseOffset("0x1a"));
		assertEquals(Integer.valueOf(0x1a), ManageTypesTool.parseOffset(" 0X1A "));
	}

	@Test
	public void aNameIsNotAnOffset() {
		assertNull(ManageTypesTool.parseOffset("count"));
		assertNull(ManageTypesTool.parseOffset(""));
	}
}
