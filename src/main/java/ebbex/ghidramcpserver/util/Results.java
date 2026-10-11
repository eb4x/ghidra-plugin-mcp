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

	/** Return a copy of {@code result} with {@code note} appended on its own line (keeps isError). */
	public static McpSchema.CallToolResult appendNote(McpSchema.CallToolResult result, String note) {
		return McpSchema.CallToolResult.builder().addTextContent(text(result) + '\n' + note)
				.isError(isError(result)).build();
	}

	/** The concatenated text content of a result. */
	public static String text(McpSchema.CallToolResult result) {
		StringBuilder sb = new StringBuilder();
		for (McpSchema.Content content : result.content()) {
			if (content instanceof McpSchema.TextContent text) {
				sb.append(text.text());
			}
		}
		return sb.toString();
	}

	public static boolean isError(McpSchema.CallToolResult result) {
		return Boolean.TRUE.equals(result.isError());
	}

	/**
	 * A hint for a substring filter that was probably meant as a regex: {@code "A|B"} as a
	 * substring matches nothing, and the empty result reads as "the lines are not there"
	 * rather than "the filter never could match". Empty when the filter has no regex
	 * metacharacters or regex mode is already on.
	 */
	public static String regexHint(String filter, boolean regex) {
		if (regex || filter == null || !REGEX_METACHARACTERS.matcher(filter).find()) {
			return "";
		}
		return "\nNote: the filter was matched as a literal substring, and '" + filter +
			"' contains regex syntax; pass regex=true if an alternation, anchor or class " +
			"was meant.";
	}

	// Brackets and parentheses are deliberately not metacharacters here: "[BX + 0x36]" and
	// "disp(reg)" are literal instruction-operand searches that work as substrings.
	private static final java.util.regex.Pattern REGEX_METACHARACTERS =
		java.util.regex.Pattern.compile("\\||\\\\[bBdDsSw]|^\\^|\\$$|\\.[*+?]");

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
