package ebbex.ghidramcpserver.util;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.util.List;
import java.util.Map;

import org.junit.Test;

/**
 * The schema fragments admit the string spelling of booleans and integers, because the MCP
 * SDK validates arguments against the server's schema before a tool runs and a client on a
 * stale schema sends new parameters as strings. The boolean one is enum-limited so "yes"
 * is refused rather than parsed as false.
 */
public class SchemasTest {

	@Test
	public void boolPropAdmitsOnlyTrueFalseAndTheirStrings() {
		Map<String, Object> prop = Schemas.boolProp("d");
		assertEquals(List.of("boolean", "string"), prop.get("type"));
		assertEquals(List.of(true, false, "true", "false"), prop.get("enum"));
		assertEquals("d", prop.get("description"));
	}

	@Test
	public void intPropAdmitsDigitStrings() {
		Map<String, Object> prop = Schemas.intProp("d");
		assertEquals(List.of("integer", "string"), prop.get("type"));
		assertTrue("42".matches((String) prop.get("pattern")));
		assertTrue("-7".matches((String) prop.get("pattern")));
		assertTrue(!"0x10".matches((String) prop.get("pattern")));
	}

	@Test
	public void sizePropAdmitsStrings() {
		assertEquals(List.of("integer", "string"), Schemas.sizeProp("d").get("type"));
	}

	@Test
	public void enumPropListsItsValues() {
		Map<String, Object> prop = Schemas.enumProp("d", List.of("a", "b"));
		assertEquals("string", prop.get("type"));
		assertEquals(List.of("a", "b"), prop.get("enum"));
	}
}
