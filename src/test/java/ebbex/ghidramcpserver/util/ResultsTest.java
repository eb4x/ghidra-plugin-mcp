package ebbex.ghidramcpserver.util;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

import io.modelcontextprotocol.spec.McpSchema;

/** The paging footer: an offset past the end is an empty page with a footer, never an error. */
public class ResultsTest {

	@Test
	public void footerForAWholeListing() {
		assertEquals("(3 total)", Results.paginationFooter(3, 0, 3));
	}

	@Test
	public void footerForAPage() {
		assertEquals("(showing 10..19 of 50; use offset/limit to page)",
			Results.paginationFooter(10, 10, 50));
	}

	@Test
	public void footerPastTheEnd() {
		assertEquals("(no results at offset 60 of 50; use offset/limit to page)",
			Results.paginationFooter(0, 60, 50));
	}

	@Test
	public void regexHintFiresOnlyForLiteralFiltersWithRegexSyntax() {
		assertTrue(Results.regexHint("Assuming DS|Neutralized", false).contains("regex=true"));
		assertTrue(Results.regexHint("\\b0x628\\b", false).contains("regex=true"));
		assertTrue(Results.regexHint("^PUSH", false).contains("regex=true"));
		assertEquals("", Results.regexHint("Assuming DS|Neutralized", true));
		assertEquals("", Results.regexHint("Assuming DS", false));
		assertEquals("operand brackets are literal", "", Results.regexHint("[BX + 0x36]", false));
		assertEquals("RISC disp(reg) is literal", "", Results.regexHint("0x4a(r6)", false));
		assertEquals("", Results.regexHint("", false));
	}

	@Test
	public void errorResultsAreFlagged() {
		McpSchema.CallToolResult error = Results.error("boom");
		assertTrue(Boolean.TRUE.equals(error.isError()));
		McpSchema.CallToolResult ok = Results.ok("fine");
		assertTrue(!Boolean.TRUE.equals(ok.isError()));
	}

	@Test
	public void appendNoteKeepsTheErrorFlag() {
		McpSchema.CallToolResult noted = Results.appendNote(Results.error("boom"), "note");
		assertTrue(Boolean.TRUE.equals(noted.isError()));
		assertTrue(((McpSchema.TextContent) noted.content().get(0)).text().contains("note"));
	}
}
