package ebbex.ghidramcpserver.util;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.util.Map;

import org.junit.Test;

/**
 * Argument parsing accepts the string spellings a client holding a pre-restart schema sends:
 * such a client passes every parameter it has never seen as a string.
 */
public class ArgsTest {

	@Test
	public void boolArgTakesBooleansAndTheirStringSpellings() {
		assertTrue(Args.boolArg(Map.of("f", true), "f", false));
		assertTrue(Args.boolArg(Map.of("f", "true"), "f", false));
		assertFalse(Args.boolArg(Map.of("f", "false"), "f", true));
		assertFalse(Args.boolArg(Map.of("f", false), "f", true));
		assertTrue(Args.boolArg(Map.of(), "f", true));
	}

	@Test
	public void intArgTakesNumbersAndDigitStrings() {
		assertEquals(7, Args.intArg(Map.of("n", 7), "n", 0));
		assertEquals(7, Args.intArg(Map.of("n", 7L), "n", 0));
		assertEquals(42, Args.intArg(Map.of("n", "42"), "n", 0));
		assertEquals(3, Args.intArg(Map.of(), "n", 3));
	}

	@Test
	public void longArgTakesHexAndNegativeStrings() {
		assertEquals(0xd1000L, Args.longArg(Map.of("n", "0xd1000"), "n", 0));
		assertEquals(0x10L, Args.longArg(Map.of("n", "0X10"), "n", 0));
		assertEquals(-16L, Args.longArg(Map.of("n", "-0x10"), "n", 0));
		assertEquals(1234L, Args.longArg(Map.of("n", "1234"), "n", 0));
		assertEquals(5L, Args.longArg(Map.of("n", 5), "n", 0));
	}

	@Test
	public void stringArgFallsBackToDefault() {
		assertEquals("x", Args.stringArg(Map.of("s", "x"), "s", null));
		assertEquals("d", Args.stringArg(Map.of(), "s", "d"));
	}
}
