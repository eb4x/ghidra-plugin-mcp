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
