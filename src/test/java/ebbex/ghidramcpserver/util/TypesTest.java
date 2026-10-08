package ebbex.ghidramcpserver.util;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.util.Map;

import org.junit.Test;

import ebbex.ghidramcpserver.RealModeProgramTest;
import ebbex.ghidramcpserver.tools.DefineTypesTool;
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

	/**
	 * A header's {@code typedef unsigned char byte} shadows the built-in: from then on every
	 * {@code byte} in a type string is a char type and the decompiler prints its values as
	 * character literals. Both the definition and each application have to say so.
	 */
	@Test
	public void aProgramTypedefShadowingABuiltinIsCalledOut() throws Exception {
		String defined = ok(new DefineTypesTool(), Map.of("source", "typedef unsigned char byte;"));
		assertTrue(defined, defined.contains("typedef byte = uchar  1 byte  new — shadows Ghidra's " +
			"built-in byte: 'byte' in a type string means the program's own /byte = uchar, a char " +
			"type: the decompiler prints its values as character literals"));

		String applied = ok(new SetDataTypeTool(new Decompilers(1)), Map.of("kind", "data",
			"address", "1000:0000", "type", "byte"));
		assertTrue(applied, applied.startsWith("Applied byte (1 bytes, typedef of uchar) — shadows " +
			"Ghidra's built-in byte:"));
		assertTrue(applied, applied.contains("character literals @ 1000:0000 = "));

		String array = ok(new SetDataTypeTool(new Decompilers(1)), Map.of("kind", "data",
			"address", "1000:0010", "type", "byte[4]"));
		assertTrue("the element type is what is judged: " + array,
			array.contains("byte[4] (4 bytes) — shadows Ghidra's built-in byte"));

		String plain = ok(new SetDataTypeTool(new Decompilers(1)), Map.of("kind", "data",
			"address", "1000:0020", "type", "short"));
		assertTrue(plain, plain.startsWith("Applied short (2 bytes) @ 1000:0020"));
	}
}
