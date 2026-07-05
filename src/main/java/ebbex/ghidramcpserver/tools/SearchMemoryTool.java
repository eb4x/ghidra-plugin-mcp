package ebbex.ghidramcpserver.tools;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import ebbex.ghidramcpserver.McpToolDef;
import ebbex.ghidramcpserver.util.Results;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import io.modelcontextprotocol.spec.McpSchema;

/** Scan memory for a byte pattern (with wildcards) or an encoded string. */
public class SearchMemoryTool implements McpToolDef {

	private static final List<String> KINDS = List.of("bytes", "text");
	private static final int DEFAULT_LIMIT = 32;

	@Override
	public String name() {
		return "search_memory";
	}

	@Override
	public String description() {
		return "Search program memory. kind=bytes matches a hex pattern where '??' is a wildcard " +
			"byte (e.g. '48 8b ?? c3'); kind=text matches an ASCII substring. Returns matching " +
			"addresses (default limit " + DEFAULT_LIMIT + ").";
	}

	@Override
	public Map<String, Object> inputSchema() {
		return Map.of(
			"type", "object",
			"properties", Map.of(
				"pattern", Results.stringProp("Hex bytes with optional '??' wildcards, or text"),
				"kind", Results.enumProp("How to interpret 'pattern' (default 'bytes')", KINDS),
				"limit", Results.intProp("Maximum matches (default " + DEFAULT_LIMIT + ")")),
			"required", List.of("pattern"));
	}

	@Override
	public boolean isReadOnly() {
		return true;
	}

	@Override
	public McpSchema.CallToolResult execute(Map<String, Object> args, Program program) {
		String pattern = Results.stringArg(args, "pattern", null);
		if (pattern == null || pattern.isBlank()) {
			return Results.error("pattern is required");
		}
		String kind = Results.stringArg(args, "kind", "bytes");
		if (!KINDS.contains(kind)) {
			return Results.error("kind must be one of " + KINDS);
		}
		int limit = Math.max(1, Results.intArg(args, "limit", DEFAULT_LIMIT));

		byte[] values;
		byte[] masks;
		if (kind.equals("text")) {
			values = pattern.getBytes(StandardCharsets.US_ASCII);
			masks = null;
		}
		else {
			try {
				byte[][] parsed = parseHexPattern(pattern);
				values = parsed[0];
				masks = parsed[1];
			}
			catch (IllegalArgumentException e) {
				return Results.error(e.getMessage());
			}
		}

		List<String> hits = new ArrayList<>();
		Address at = program.getMinAddress();
		Address end = program.getMaxAddress();
		while (at != null && hits.size() < limit) {
			Address found = program.getMemory().findBytes(at, end, values, masks, true,
				TaskMonitor.DUMMY);
			if (found == null) {
				break;
			}
			hits.add(found + describeContainer(program, found));
			at = found.next();
		}

		if (hits.isEmpty()) {
			return Results.ok("No matches for " + kind + " pattern");
		}
		return Results.ok(String.join("\n", hits) +
			(hits.size() == limit ? "\n(stopped at limit " + limit + ")" : "\n(" + hits.size() +
				" matches)"));
	}

	/** "  in <function>+0x.." when the hit falls inside a function, else "". */
	private static String describeContainer(Program program, Address address) {
		Function function = program.getFunctionManager().getFunctionContaining(address);
		if (function == null) {
			return "";
		}
		long offset = address.subtract(function.getEntryPoint());
		return "  in " + function.getName() + (offset != 0 ? "+0x" + Long.toHexString(offset) : "");
	}

	/** Returns {values, masks}; a wildcard byte has value 0 and mask 0. */
	private static byte[][] parseHexPattern(String pattern) {
		String[] tokens = pattern.trim().split("\\s+");
		byte[] values = new byte[tokens.length];
		byte[] masks = new byte[tokens.length];
		for (int i = 0; i < tokens.length; i++) {
			String token = tokens[i];
			if (token.equals("??") || token.equals("..")) {
				values[i] = 0;
				masks[i] = 0;
			}
			else {
				if (token.length() != 2) {
					throw new IllegalArgumentException(
						"Each hex byte must be 2 chars or '??': got '" + token + "'");
				}
				values[i] = (byte) Integer.parseInt(token, 16);
				masks[i] = (byte) 0xff;
			}
		}
		return new byte[][] { values, masks };
	}
}
