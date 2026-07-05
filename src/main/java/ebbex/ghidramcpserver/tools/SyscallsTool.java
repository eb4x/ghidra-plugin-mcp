package ebbex.ghidramcpserver.tools;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import ebbex.ghidramcpserver.McpToolDef;
import ebbex.ghidramcpserver.util.ProgramContext;
import ebbex.ghidramcpserver.util.Results;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.scalar.Scalar;
import io.modelcontextprotocol.spec.McpSchema;

/**
 * List the software-interrupt call sites in a function with the DOS/BIOS function
 * resolved from the AH selector — the datum the decompiler drops (it renders
 * {@code INT 21h} as an opaque {@code swi(0x21)}). This is the fastest way to see
 * what a 16-bit DOS routine actually does.
 */
public class SyscallsTool implements McpToolDef {

	private static final int MAX_INSTRUCTIONS = 20000;

	@Override
	public String name() {
		return "syscalls";
	}

	@Override
	public String description() {
		return "List the software interrupts (INT 21h DOS, INT 10h video, etc.) a function issues, " +
			"each with the AH function code resolved from the preceding MOV AH/AX and a name for " +
			"common DOS calls. Recovers what the decompiler hides behind swi(0x21).";
	}

	@Override
	public Map<String, Object> inputSchema() {
		return Map.of(
			"type", "object",
			"properties", Map.of(
				"function", Results.stringProp("Function name or an address within it"),
				"target", Results.stringProp("Alias for 'function'"),
				"address", Results.stringProp("Alias for 'function'")));
	}

	@Override
	public boolean isReadOnly() {
		return true;
	}

	@Override
	public McpSchema.CallToolResult execute(Map<String, Object> args, Program program) {
		String ref = Results.locationArg(args);
		if (ref == null) {
			return Results.error("a function (name or address) is required");
		}
		Function function = ProgramContext.findFunction(program, ref);

		List<String> lines = new ArrayList<>();
		InstructionIterator it =
			program.getListing().getInstructions(function.getEntryPoint(), true);
		int ah = -1; // -1 = unknown
		int seen = 0;
		while (it.hasNext() && seen < MAX_INSTRUCTIONS) {
			Instruction ins = it.next();
			if (program.getFunctionManager().getFunctionContaining(ins.getAddress()) != function) {
				break;
			}
			seen++;
			String mnem = ins.getMnemonicString();
			if (mnem.equalsIgnoreCase("INT")) {
				Scalar vector = ins.getScalar(0);
				long intNum = vector != null ? vector.getUnsignedValue() : -1;
				lines.add(ins.getAddress() + "  INT " + Long.toHexString(intNum) + "h  " +
					(ah >= 0 ? "AH=" + hex(ah) + "  " + describe(intNum, ah) : "AH=?"));
				continue;
			}
			ah = updateAh(ah, ins, mnem);
		}

		if (lines.isEmpty()) {
			return Results.ok(function.getName() + " issues no software interrupts.");
		}
		return Results.ok(function.getName() + " syscalls:\n" + String.join("\n", lines) +
			"\n(" + lines.size() + " call site(s))");
	}

	/** Track AH across the simple patterns that precede a DOS/BIOS call. */
	private static int updateAh(int ah, Instruction ins, String mnem) {
		Register reg0 = ins.getRegister(0);
		String r0 = reg0 != null ? reg0.getName() : null;
		if (mnem.equalsIgnoreCase("MOV") && r0 != null) {
			Scalar imm = ins.getScalar(1);
			if (imm != null) {
				if (r0.equalsIgnoreCase("AH")) {
					return (int) (imm.getUnsignedValue() & 0xff);
				}
				if (r0.equalsIgnoreCase("AX")) {
					return (int) ((imm.getUnsignedValue() >> 8) & 0xff);
				}
			}
			else if (r0.equalsIgnoreCase("AH") || r0.equalsIgnoreCase("AX")) {
				return -1; // AH set from a non-immediate
			}
		}
		else if ((mnem.equalsIgnoreCase("SUB") || mnem.equalsIgnoreCase("XOR")) && r0 != null) {
			Register reg1 = ins.getRegister(1);
			if (reg1 != null && r0.equalsIgnoreCase(reg1.getName()) &&
				(r0.equalsIgnoreCase("AH") || r0.equalsIgnoreCase("AX"))) {
				return 0;
			}
		}
		else if (mnem.equalsIgnoreCase("CALL")) {
			return -1; // callee may clobber AH
		}
		return ah;
	}

	private static String hex(long v) {
		return "0x" + Long.toHexString(v);
	}

	/** Names for the common INT 21h (DOS) function codes; other vectors get no name. */
	private static String describe(long intNum, int ah) {
		if (intNum != 0x21) {
			return "";
		}
		return switch (ah) {
			case 0x02 -> "putchar";
			case 0x06 -> "direct console I/O";
			case 0x09 -> "print $-string";
			case 0x0e -> "select drive";
			case 0x19 -> "get drive";
			case 0x1a -> "set DTA";
			case 0x25 -> "set interrupt vector";
			case 0x2a -> "get date";
			case 0x2c -> "get time";
			case 0x2f -> "get DTA";
			case 0x30 -> "get DOS version";
			case 0x35 -> "get interrupt vector";
			case 0x39 -> "mkdir";
			case 0x3a -> "rmdir";
			case 0x3b -> "chdir";
			case 0x3c -> "create/truncate file";
			case 0x3d -> "open file";
			case 0x3e -> "close file";
			case 0x3f -> "read file/device";
			case 0x40 -> "write file/device";
			case 0x41 -> "delete file";
			case 0x42 -> "lseek";
			case 0x43 -> "get/set attributes";
			case 0x44 -> "ioctl";
			case 0x47 -> "get cwd";
			case 0x48 -> "allocate memory";
			case 0x49 -> "free memory";
			case 0x4a -> "resize memory block";
			case 0x4b -> "exec/load program";
			case 0x4c -> "terminate (exit)";
			case 0x4e -> "find first";
			case 0x4f -> "find next";
			case 0x56 -> "rename file";
			case 0x57 -> "get/set file date";
			default -> "DOS fn " + hex(ah);
		};
	}
}
