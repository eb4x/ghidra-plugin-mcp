package ebbex.ghidramcpserver.tools;

import java.util.List;
import java.util.Map;

import ebbex.ghidramcpserver.McpToolDef;
import ebbex.ghidramcpserver.util.ProgramContext;
import ebbex.ghidramcpserver.util.Results;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import io.modelcontextprotocol.spec.McpSchema;

/** Raw memory dump as hex + ASCII. */
public class ReadBytesTool implements McpToolDef {

	private static final int MAX_LENGTH = 4096;

	@Override
	public String name() {
		return "read_bytes";
	}

	@Override
	public String description() {
		return "Read raw bytes from program memory and return them as a hex dump with an ASCII " +
			"column. Length is capped at " + MAX_LENGTH + " bytes.";
	}

	@Override
	public Map<String, Object> inputSchema() {
		return Map.of(
			"type", "object",
			"properties", Map.of(
				"address", Results.stringProp("Start address"),
				"length", Results.intProp("Number of bytes (max " + MAX_LENGTH + ")")),
			"required", List.of("address", "length"));
	}

	@Override
	public boolean isReadOnly() {
		return true;
	}

	@Override
	public McpSchema.CallToolResult execute(Map<String, Object> args, Program program)
			throws Exception {
		String addressArg = Results.stringArg(args, "address", null);
		if (addressArg == null) {
			return Results.error("address is required");
		}
		int length = Results.intArg(args, "length", 0);
		if (length <= 0) {
			return Results.error("length must be positive");
		}
		length = Math.min(length, MAX_LENGTH);

		Address start = ProgramContext.parseAddress(program, addressArg);
		byte[] buffer = new byte[length];
		int read = program.getMemory().getBytes(start, buffer);

		return Results.ok(hexDump(start, buffer, read));
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
