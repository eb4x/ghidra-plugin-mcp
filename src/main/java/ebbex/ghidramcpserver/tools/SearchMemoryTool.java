package ebbex.ghidramcpserver.tools;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import ebbex.ghidramcpserver.ProgramTool;
import ebbex.ghidramcpserver.util.Args;
import ebbex.ghidramcpserver.util.Results;
import ebbex.ghidramcpserver.util.Schemas;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import io.modelcontextprotocol.spec.McpSchema;

/** Scan memory for a byte pattern (with wildcards) or an encoded string. */
public class SearchMemoryTool implements ProgramTool {

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
				"pattern", Schemas.stringProp("Hex bytes with optional '??' wildcards, or text"),
				"kind", Schemas.enumProp("How to interpret 'pattern' (default 'bytes')", KINDS),
				"offset", Schemas.intProp("Skip this many matches (for paging; default 0)"),
				"limit", Schemas.intProp("Maximum matches to return (default " + DEFAULT_LIMIT + ")")),
			"required", List.of("pattern"));
	}

	@Override
	public boolean isReadOnly() {
		return true;
	}

	@Override
	public McpSchema.CallToolResult execute(Map<String, Object> args, Program program) {
		String pattern = Args.stringArg(args, "pattern", null);
		if (pattern == null || pattern.isBlank()) {
			return Results.error("pattern is required");
		}
		String kind = Args.stringArg(args, "kind", "bytes");
		if (!KINDS.contains(kind)) {
			return Results.error("kind must be one of " + KINDS);
		}
		int limit = Math.max(1, Args.intArg(args, "limit", DEFAULT_LIMIT));
		int offset = Math.max(0, Args.intArg(args, "offset", 0));

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
		int index = 0;
		boolean more = false;
		while (at != null) {
			Address found = program.getMemory().findBytes(at, end, values, masks, true,
				TaskMonitor.DUMMY);
			if (found == null) {
				break;
			}
			if (index >= offset) {
				if (hits.size() < limit) {
					hits.add(found + describeContainer(program, found));
				}
				else {
					more = true;
					break;
				}
			}
			index++;
			at = found.next();
		}

		if (hits.isEmpty()) {
			return Results.ok("No matches for " + kind + " pattern" +
				(offset > 0 ? " at offset " + offset : ""));
		}
		String footer = more
				? "\n(" + hits.size() + " matches from offset " + offset +
					"; more available — raise 'limit' or page with 'offset')"
				: "\n(" + hits.size() + " matches from offset " + offset + "; end of results)";
		return Results.ok(String.join("\n", hits) + footer);
	}

	/**
	 * "  in &lt;function&gt;+0x.." when the hit falls inside a function, else "".
	 * The +offset is only shown when it is sane — in 16-bit segmented programs a hit and
	 * a function entry can live under different segment bases, which makes the raw address
	 * subtraction produce a garbage (huge/negative) offset, so we suppress it there.
	 */
	private static String describeContainer(Program program, Address address) {
		Function function = program.getFunctionManager().getFunctionContaining(address);
		if (function == null) {
			return "";
		}
		Address entry = function.getEntryPoint();
		if (address.getAddressSpace().equals(entry.getAddressSpace())) {
			try {
				long offset = address.subtract(entry);
				if (offset > 0 && offset <= function.getBody().getNumAddresses()) {
					return "  in " + function.getName() + "+0x" + Long.toHexString(offset);
				}
			}
			catch (Exception e) {
				// fall through to name-only
			}
		}
		return "  in " + function.getName();
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
