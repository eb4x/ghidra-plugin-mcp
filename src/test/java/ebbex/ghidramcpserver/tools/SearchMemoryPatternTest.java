package ebbex.ghidramcpserver.tools;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

import org.junit.Test;

/** The hex pattern grammar behind search_memory kind=bytes, and instruction-text normalising. */
public class SearchMemoryPatternTest {

	@Test
	public void wildcardsHaveAZeroMask() {
		byte[][] parsed = SearchMemoryTool.parseHexPattern("48 8b ?? c3");
		assertArrayEquals(new byte[] { 0x48, (byte) 0x8b, 0, (byte) 0xc3 }, parsed[0]);
		assertArrayEquals(new byte[] { (byte) 0xff, (byte) 0xff, 0, (byte) 0xff }, parsed[1]);
	}

	@Test
	public void dotsAreWildcardsToo() {
		byte[][] parsed = SearchMemoryTool.parseHexPattern("  cd .. 21 ");
		assertArrayEquals(new byte[] { (byte) 0xff, 0, (byte) 0xff }, parsed[1]);
	}

	@Test(expected = IllegalArgumentException.class)
	public void aThreeDigitByteIsRefused() {
		SearchMemoryTool.parseHexPattern("48 8bc c3");
	}

	@Test
	public void instructionTextIsUppercasedAndSpaceCollapsed() {
		assertEquals("JMP WORD PTR CS:[BX + 0X628]",
			SearchMemoryTool.normalizeInstructionText("  jmp   word ptr cs:[BX + 0x628] "));
	}
}
