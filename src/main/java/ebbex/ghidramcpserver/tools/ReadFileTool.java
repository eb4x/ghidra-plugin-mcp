package ebbex.ghidramcpserver.tools;

import java.io.File;
import java.io.RandomAccessFile;
import java.util.List;
import java.util.Map;

import ebbex.ghidramcpserver.ProgramTool;
import ebbex.ghidramcpserver.util.Args;
import ebbex.ghidramcpserver.util.Results;
import ebbex.ghidramcpserver.util.Schemas;
import ghidra.program.model.listing.Program;
import io.modelcontextprotocol.spec.McpSchema;

/**
 * Read raw bytes from the program's executable file on disk by file offset —
 * independent of what Ghidra mapped into memory. Needed for overlay/packed
 * payloads appended past the loaded image (e.g. bound DOS extenders), which
 * read_bytes (address-space only) cannot see.
 */
public class ReadFileTool implements ProgramTool {

	private static final int MAX_LENGTH = 4096;

	@Override
	public String name() {
		return "read_file";
	}

	@Override
	public String description() {
		return "Read raw bytes from the program's on-disk executable file by file offset (hex dump " +
			"+ ASCII). Unlike read_bytes (which reads Ghidra's loaded address space), this sees the " +
			"whole file including overlays/packed payload appended past the loaded image. Length " +
			"capped at " + MAX_LENGTH + ".";
	}

	@Override
	public Map<String, Object> inputSchema() {
		return Map.of(
			"type", "object",
			"properties", Map.of(
				"offset", Schemas.intProp("Byte offset into the file"),
				"length", Schemas.intProp("Number of bytes (max " + MAX_LENGTH + ")")),
			"required", List.of("offset", "length"));
	}

	@Override
	public boolean isReadOnly() {
		return true;
	}

	@Override
	public McpSchema.CallToolResult execute(Map<String, Object> args, Program program)
			throws Exception {
		long offset = Args.intArg(args, "offset", -1);
		if (offset < 0) {
			return Results.error("offset is required (>= 0)");
		}
		int length = Args.intArg(args, "length", 0);
		if (length <= 0) {
			return Results.error("length must be positive");
		}
		length = Math.min(length, MAX_LENGTH);

		String path = program.getExecutablePath();
		File file = new File(path);
		if (!file.isFile()) {
			return Results.error("Executable file not found on disk: " + path +
				" (imported from elsewhere, or the path moved).");
		}
		long fileLen = file.length();
		if (offset >= fileLen) {
			return Results.error("offset " + offset + " is past end of file (" + fileLen + " bytes)");
		}

		int toRead = (int) Math.min(length, fileLen - offset);
		byte[] buffer = new byte[toRead];
		try (RandomAccessFile raf = new RandomAccessFile(file, "r")) {
			raf.seek(offset);
			raf.readFully(buffer);
		}

		return Results.ok("file " + path + " (" + fileLen + " bytes)\n" + hexDump(offset, buffer));
	}

	private static String hexDump(long start, byte[] buffer) {
		StringBuilder sb = new StringBuilder();
		for (int row = 0; row < buffer.length; row += 16) {
			sb.append(String.format("%08x  ", start + row));
			StringBuilder ascii = new StringBuilder();
			for (int i = 0; i < 16; i++) {
				if (row + i < buffer.length) {
					int b = buffer[row + i] & 0xff;
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
