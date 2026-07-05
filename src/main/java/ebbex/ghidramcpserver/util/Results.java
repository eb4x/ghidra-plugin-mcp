package ebbex.ghidramcpserver.util;

import io.modelcontextprotocol.spec.McpSchema;

/** Factories for MCP tool results. */
public final class Results {

	private Results() {
	}

	public static McpSchema.CallToolResult ok(String text) {
		return McpSchema.CallToolResult.builder().addTextContent(text).build();
	}

	public static McpSchema.CallToolResult error(String message) {
		return McpSchema.CallToolResult.builder().addTextContent(message).isError(true).build();
	}

	/** Footer line for paginated listings. */
	public static String paginationFooter(int shown, int offset, int total) {
		if (total <= shown && offset == 0) {
			return "(" + total + " total)";
		}
		if (shown == 0) {
			return "(no results at offset " + offset + " of " + total +
				"; use offset/limit to page)";
		}
		return "(showing " + offset + ".." + (offset + shown - 1) + " of " + total +
			"; use offset/limit to page)";
	}
}
