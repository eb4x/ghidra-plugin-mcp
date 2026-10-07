package ebbex.ghidramcpserver.tools;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Predicate;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;
import java.util.Map;

import ebbex.ghidramcpserver.ProgramTool;
import ebbex.ghidramcpserver.util.Args;
import ebbex.ghidramcpserver.util.Results;
import ebbex.ghidramcpserver.util.Schemas;
import ghidra.program.model.address.Address;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.address.SegmentedAddress;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import io.modelcontextprotocol.spec.McpSchema;

/** Scan memory for a byte pattern (with wildcards), an encoded string, or instruction text. */
public class SearchMemoryTool implements ProgramTool {

	private static final List<String> KINDS = List.of("bytes", "text", "instruction");
	private static final List<String> SOURCES = List.of("memory", "file");
	private static final int DEFAULT_LIMIT = 32;

	/** source=file reads the whole file into memory; firmware and executables sit far below. */
	private static final long MAX_FILE_BYTES = 512L * 1024 * 1024;

	@Override
	public String name() {
		return "search_memory";
	}

	@Override
	public String description() {
		return "Search program memory. kind=bytes matches a hex pattern where '??' is a wildcard " +
			"byte (e.g. '48 8b ?? c3'); kind=text matches an ASCII substring; kind=instruction " +
			"matches disassembled instruction text case-insensitively (e.g. 'JMP word ptr CS:' " +
			"or 'MOV AX' — a substring of mnemonic + operands as the listing prints them; " +
			"regex=true makes it a Java regex over the same uppercased, space-collapsed text, " +
			"so a constant can be anchored: '\\b0x628\\b' no longer matches 0x6288). " +
			"Returns matching addresses (default limit " + DEFAULT_LIMIT + "). source=file scans " +
			"the program's on-disk file instead (kind=bytes|text), returning FILE OFFSETS — " +
			"pasteable into read_file — each with the address(es) it is loaded at in this program, " +
			"or 'not loaded' (a header says instead when the program's loader kept no file-offset " +
			"records, so placement is unknown). It scans the file THIS program was imported " +
			"from: a program imported from a pre-split slice only sees that slice. That covers images larger than the language's address space (a " +
			"banked 8051 flash) and payloads no block maps, without a throwaway re-import.";
	}

	@Override
	public Map<String, Object> inputSchema() {
		return Map.of(
			"type", "object",
			"properties", Map.of(
				"pattern", Schemas.stringProp(
					"Hex bytes with optional '??' wildcards, text, or instruction-text substring"),
				"kind", Schemas.enumProp("How to interpret 'pattern' (default 'bytes')", KINDS),
				"source", Schemas.enumProp("What to scan: memory (default, the loaded address " +
					"space) or file (the program's on-disk file, by offset)", SOURCES),
				"offset", Schemas.intProp("Skip this many matches (for paging; default 0)"),
				"limit", Schemas.intProp("Maximum matches to return (default " + DEFAULT_LIMIT + ")"),
				"regex", Schemas.boolProp("kind=instruction only: treat 'pattern' as a regex " +
					"(case-insensitive, matched anywhere in the instruction text) instead of a " +
					"substring (default false)")),
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
		String source = Args.stringArg(args, "source", "memory");
		if (!SOURCES.contains(source)) {
			return Results.error("source must be one of " + SOURCES);
		}
		if (source.equals("file") && kind.equals("instruction")) {
			return Results.error("source=file scans raw bytes, so it takes kind=bytes|text — " +
				"instructions only exist in the loaded address space");
		}
		int limit = Math.max(1, Args.intArg(args, "limit", DEFAULT_LIMIT));
		int offset = Math.max(0, Args.intArg(args, "offset", 0));

		if (kind.equals("instruction")) {
			return searchInstructions(program, pattern, Args.boolArg(args, "regex", false), offset,
				limit);
		}

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

		if (source.equals("file")) {
			return searchFile(program, kind, values, masks, offset, limit);
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
					hits.add(blockRelative(program, found) + describeContainer(program, found));
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
	 * Scan the program's on-disk file by offset. The file is what the program was imported
	 * from ({@code getExecutablePath}), so it can hold far more than the program maps — the
	 * case that used to force a second, meaningless raw import just to make every offset
	 * searchable. Each hit says where (if anywhere) this program loaded those bytes.
	 */
	private static McpSchema.CallToolResult searchFile(Program program, String kind,
			byte[] values, byte[] masks, int offset, int limit) {
		String path = program.getExecutablePath();
		File file = path == null ? null : new File(path);
		if (file == null || !file.isFile()) {
			return Results.error("The program's on-disk file is not available: " + path +
				" (imported from elsewhere, or the file moved) — source=file needs it.");
		}
		if (file.length() > MAX_FILE_BYTES) {
			return Results.error(path + " is " + file.length() + " bytes; source=file scans at " +
				"most " + MAX_FILE_BYTES + ".");
		}
		byte[] data;
		try {
			data = Files.readAllBytes(file.toPath());
		}
		catch (IOException e) {
			return Results.error("Could not read " + path + ": " + e.getMessage());
		}

		// Load addresses come from the program's FileBytes records. A loader that builds its
		// blocks from plain byte arrays keeps none, and then every hit would read "not loaded"
		// — including the very bytes the program holds. Say the mapping is unknown instead.
		boolean mapped = !program.getMemory().getAllFileBytes().isEmpty();
		List<String> hits = new ArrayList<>();
		int index = 0;
		boolean more = false;
		for (int at = 0; at + values.length <= data.length; at++) {
			if (!matchesAt(data, at, values, masks)) {
				continue;
			}
			if (index++ < offset) {
				continue;
			}
			if (hits.size() == limit) {
				more = true;
				break;
			}
			hits.add(String.format("0x%x", at) + (mapped ? loadedAt(program, at) : ""));
		}

		String header = "file " + path + " (" + data.length + " bytes)\n" + (mapped ? ""
				: "(this program's loader kept no file-offset records, so where each hit is " +
					"loaded is unknown — not the same as unloaded)\n");
		if (hits.isEmpty()) {
			return Results.ok(header + "No matches for " + kind + " pattern in the file" +
				(offset > 0 ? " at offset " + offset : ""));
		}
		String footer = more
				? "\n(" + hits.size() + " matches from offset " + offset +
					"; more available — raise 'limit' or page with 'offset')"
				: "\n(" + hits.size() + " matches from offset " + offset + "; end of results)";
		return Results.ok(header + String.join("\n", hits) + footer);
	}

	private static boolean matchesAt(byte[] data, int at, byte[] values, byte[] masks) {
		for (int i = 0; i < values.length; i++) {
			int mask = masks == null ? 0xff : masks[i] & 0xff;
			if ((data[at + i] & mask) != (values[i] & mask)) {
				return false;
			}
		}
		return true;
	}

	/** "  -> addr" for each place this program loaded the offset, or "  (not loaded here)". */
	private static String loadedAt(Program program, long fileOffset) {
		List<Address> addresses = program.getMemory().locateAddressesForFileOffset(fileOffset);
		if (addresses.isEmpty()) {
			return "  (not loaded in this program)";
		}
		StringBuilder sb = new StringBuilder("  ->");
		for (Address address : addresses) {
			sb.append(' ').append(blockRelative(program, address))
					.append(describeContainer(program, address));
		}
		return sb.toString();
	}

	/**
	 * Scan disassembled instructions for a text substring. Both sides are uppercased and
	 * whitespace-collapsed, so 'jmp word ptr cs:' matches however the listing spaces it.
	 * The full instruction text is echoed per hit, since the pattern only matched part of it.
	 */
	private static McpSchema.CallToolResult searchInstructions(Program program, String pattern,
			boolean regex, int offset, int limit) {
		// A substring cannot say "this constant and not a longer one": '0x628' also matched
		// 0x6288, 0x6286 and 0x6280, burying the one real hit. A regex can (\b0x628\b).
		Predicate<String> matches;
		if (regex) {
			try {
				matches = Pattern.compile(pattern, Pattern.CASE_INSENSITIVE).asPredicate();
			}
			catch (PatternSyntaxException e) {
				return Results.error("regex=true but 'pattern' is not a valid regex: " +
					e.getDescription() + " at index " + e.getIndex());
			}
		}
		else {
			String needle = normalizeInstructionText(pattern);
			matches = text -> text.contains(needle);
		}
		List<String> hits = new ArrayList<>();
		int index = 0;
		boolean more = false;
		for (Instruction instruction : program.getListing().getInstructions(true)) {
			if (!matches.test(normalizeInstructionText(instruction.toString()))) {
				continue;
			}
			if (index >= offset) {
				if (hits.size() < limit) {
					hits.add(blockRelative(program, instruction.getAddress()) + "  " + instruction +
						describeContainer(program, instruction.getAddress()));
				}
				else {
					more = true;
					break;
				}
			}
			index++;
		}
		if (hits.isEmpty()) {
			return Results.ok("No instructions matching '" + pattern + "'" +
				(offset > 0 ? " at offset " + offset : "") +
				"\nNote: only disassembled instructions are searched — bytes not yet " +
				"disassembled never match; use kind=bytes for those.");
		}
		String footer = more
				? "\n(" + hits.size() + " matches from offset " + offset +
					"; more available — raise 'limit' or page with 'offset')"
				: "\n(" + hits.size() + " matches from offset " + offset + "; end of results)";
		return Results.ok(String.join("\n", hits) + footer);
	}

	/**
	 * Memory.findBytes hands back a segmented hit in the image base's framing
	 * ({@code 1000:xxxx} for everything), while every other tool speaks the containing
	 * block's {@code seg:off}. Re-frame it on the block's segment so a hit can be pasted
	 * straight into read_bytes / inspect without a linear conversion.
	 */
	private static String blockRelative(Program program, Address address) {
		if (address instanceof SegmentedAddress hit) {
			MemoryBlock block = program.getMemory().getBlock(address);
			if (block != null && block.getStart() instanceof SegmentedAddress start) {
				return hit.normalize(start.getSegment()).toString();
			}
		}
		return address.toString();
	}

	static String normalizeInstructionText(String text) {
		return text.trim().replaceAll("\\s+", " ").toUpperCase();
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
	static byte[][] parseHexPattern(String pattern) {
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
