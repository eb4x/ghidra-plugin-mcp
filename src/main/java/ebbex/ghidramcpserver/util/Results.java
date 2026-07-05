package ebbex.ghidramcpserver.util;

import java.util.List;
import java.util.Map;

import io.modelcontextprotocol.spec.McpSchema;

/** Factories for tool results and small schema/argument helpers. */
public final class Results {

	private Results() {
	}

	public static McpSchema.CallToolResult ok(String text) {
		return McpSchema.CallToolResult.builder().addTextContent(text).build();
	}

	public static McpSchema.CallToolResult error(String message) {
		return McpSchema.CallToolResult.builder().addTextContent(message).isError(true).build();
	}

	/** Schema fragment for a string property with a description. */
	public static Map<String, Object> stringProp(String description) {
		return Map.of("type", "string", "description", description);
	}

	/** Schema fragment for an integer property with a description. */
	public static Map<String, Object> intProp(String description) {
		return Map.of("type", "integer", "description", description);
	}

	/** Schema fragment for a string enum property. */
	public static Map<String, Object> enumProp(String description, List<String> values) {
		return Map.of("type", "string", "description", description, "enum", values);
	}

	public static String stringArg(Map<String, Object> args, String key, String defaultValue) {
		Object v = args.get(key);
		return v == null ? defaultValue : v.toString();
	}

	public static int intArg(Map<String, Object> args, String key, int defaultValue) {
		Object v = args.get(key);
		if (v == null) {
			return defaultValue;
		}
		if (v instanceof Number n) {
			return n.intValue();
		}
		return Integer.parseInt(v.toString());
	}

	public static boolean boolArg(Map<String, Object> args, String key, boolean defaultValue) {
		Object v = args.get(key);
		if (v == null) {
			return defaultValue;
		}
		if (v instanceof Boolean b) {
			return b;
		}
		return Boolean.parseBoolean(v.toString());
	}

	/** Footer line for paginated listings. */
	public static String paginationFooter(int shown, int offset, int total) {
		if (total <= shown && offset == 0) {
			return "(" + total + " total)";
		}
		return "(showing " + offset + ".." + (offset + shown - 1) + " of " + total +
			"; use offset/limit to page)";
	}
}
