package ebbex.ghidramcpserver.util;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.util.Map;

import org.junit.Test;

import ebbex.ghidramcpserver.RealModeProgramTest;
import ebbex.ghidramcpserver.tools.SetDataTypeTool;

/**
 * {@code uint8} is not a Ghidra type, and the refusal has to say what is: the 1-byte names,
 * and which of them print as character literals.
 */
public class TypesTest extends RealModeProgramTest {

	@Test
	public void widthSpellingsGetTheGhidraNames() {
		assertTrue(Types.widthHint("uint8").contains("1-byte integers are: byte (unsigned), sbyte"));
		assertTrue(Types.widthHint("uint8_t *").contains("1-byte"));
		assertTrue(Types.widthHint("INT16_t").contains("2-byte integers are: short"));
		assertTrue(Types.widthHint("uint32_t").contains("<stdint.h> names are typedefs"));
		assertEquals("a real Ghidra type that failed for another reason gets no hint", "",
			Types.widthHint("uint16"));
		assertEquals("", Types.widthHint("RoomDat"));
		assertEquals("", Types.widthHint("uint"));
	}

	@Test
	public void unrecognizedWidthSpellingIsRefusedWithTheNames() throws Exception {
		String refused = error(new SetDataTypeTool(new Decompilers(1)), Map.of("kind", "data",
			"address", "1000:0000", "type", "uint8"));
		assertTrue(refused, refused.contains("no built-in 'uint8'"));
		assertTrue(refused, refused.contains("char, uchar and schar"));
	}
}
