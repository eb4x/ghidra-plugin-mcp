package ebbex.ghidramcpserver.tools;

import java.util.List;
import java.util.Map;

import ebbex.ghidramcpserver.ProgramTool;
import ebbex.ghidramcpserver.util.Args;
import ebbex.ghidramcpserver.util.Locations;
import ebbex.ghidramcpserver.util.Results;
import ebbex.ghidramcpserver.util.Schemas;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import io.modelcontextprotocol.spec.McpSchema;

/** Raw memory dump as hex + ASCII. */
public class ReadBytesTool implements ProgramTool {

	private static final int MAX_LENGTH = 4096;

	@Override
	public String name() {
		return "read_bytes";
	}

	@Override
	public String description() {
		return "Read raw bytes from program memory and return them as a hex dump with an ASCII " +
			"column. Length is capped at " + MAX_LENGTH + " bytes. A failure distinguishes an " +
			"address that is mapped nowhere from one inside an UNINITIALIZED block — the latter " +
			"means the executable holds no bytes there because the contents are built at run " +
			"time, which is an answer about the data rather than a bad call.";
	}

	@Override
	public Map<String, Object> inputSchema() {
		return Map.of(
			"type", "object",
			"properties", Map.of(
				"address", Schemas.stringProp("Start address"),
				"length", Schemas.intProp("Number of bytes (max " + MAX_LENGTH + ")")),
			"required", List.of("address", "length"));
	}

	@Override
	public boolean isReadOnly() {
		return true;
	}

	@Override
	public McpSchema.CallToolResult execute(Map<String, Object> args, Program program)
			throws Exception {
		String addressArg = Args.stringArg(args, "address", null);
		if (addressArg == null) {
			return Results.error("address is required");
		}
		int length = Args.intArg(args, "length", 0);
		if (length <= 0) {
			return Results.error("length must be positive");
		}
		length = Math.min(length, MAX_LENGTH);

		Address start = Locations.parseAddress(program, addressArg);
		Memory memory = program.getMemory();
		byte[] buffer = new byte[length];
		int read;
		try {
			read = memory.getBytes(start, buffer);
		}
		catch (MemoryAccessException e) {
			// Diagnosed here rather than pre-checked, so the successful path is untouched and the
			// explanation can never disagree with what the read actually did.
			return Results.error(explainUnreadable(memory, start, e));
		}

		String dump = hexDump(start, buffer, read);
		if (read < length) {
			dump += "(read " + read + " of " + length + " requested — the range runs off the end " +
				"of readable memory" + boundary(start, read) + ")\n";
		}
		return Results.ok(dump);
	}

	/**
	 * Why a read failed, in terms the caller can act on.
	 *
	 * <p>Ghidra reports both "your address is wrong" and "the image never contained these bytes"
	 * as the same {@code MemoryAccessException: Unable to read bytes at …}, and the first reading
	 * of that is always the former. The distinction matters because the second case is not a
	 * failure to work around — it is the answer. Bytes in an uninitialized block are absent from
	 * the executable because something builds them at run time, which is usually the fact you
	 * were trying to establish, and it points at the code that writes them.
	 */
	private static String explainUnreadable(Memory memory, Address start,
			MemoryAccessException e) {
		MemoryBlock block = memory.getBlock(start);
		if (block == null) {
			return "Nothing is mapped at " + start + " — it falls in no memory block at all, so " +
				"either the address is wrong or that region was never loaded. " +
				"list kind=segments shows what is mapped.";
		}
		if (!block.isInitialized()) {
			return start + " is inside '" + block.getName() + "' (" + block.getStart() + "-" +
				block.getEnd() + "), an UNINITIALIZED block — the executable carries no bytes " +
				"for it, so there is nothing here to read and never was. That is usually the " +
				"answer rather than a problem: whatever lives here is produced at run time. Find " +
				"what builds it with xrefs direction=to location=" + start + " and look for a " +
				"WRITE, which typically names the loader or parser that fills it in.";
		}
		return "Could not read " + start + ", which is in initialized block '" + block.getName() +
			"': " + e.getMessage();
	}

	/** {@code " at <addr>"} for where readable memory stopped, or nothing if that overflows. */
	private static String boundary(Address start, int read) {
		try {
			return " at " + start.add(read);
		}
		catch (Exception e) {
			// add() throws past the end of a segment; the count above already says enough.
			return "";
		}
	}

	private static String hexDump(Address start, byte[] buffer, int length) {
		StringBuilder sb = new StringBuilder();
		for (int offset = 0; offset < length; offset += 16) {
			Address lineAddr = start.add(offset);
			sb.append(lineAddr).append("  ");
			StringBuilder ascii = new StringBuilder();
			for (int i = 0; i < 16; i++) {
				if (offset + i < length) {
					int b = buffer[offset + i] & 0xff;
					sb.append(String.format("%02x ", b));
					ascii.append(b >= 0x20 && b < 0x7f ? (char) b : '.');
				}
				else {
					sb.append("   ");
				}
				if (i == 7) {
					sb.append(' ');
				}
			}
			sb.append(" |").append(ascii).append("|\n");
		}
		return sb.toString();
	}
}
