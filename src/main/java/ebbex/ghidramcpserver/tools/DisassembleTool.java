package ebbex.ghidramcpserver.tools;

import java.util.Map;

import ebbex.ghidramcpserver.ProgramTool;
import ebbex.ghidramcpserver.util.Args;
import ebbex.ghidramcpserver.util.Locations;
import ebbex.ghidramcpserver.util.Results;
import ebbex.ghidramcpserver.util.Schemas;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.CodeUnitFormat;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.StackReference;
import io.modelcontextprotocol.spec.McpSchema;

/** Disassembly listing for a function, or a run of instructions from an address. */
public class DisassembleTool implements ProgramTool {

	private static final int DEFAULT_COUNT = 32;
	private static final int MAX_COUNT = 4096;

	@Override
	public String name() {
		return "disassemble";
	}

	@Override
	public String description() {
		return "Show disassembly. Give a 'function' (name or contained address) to disassemble a " +
			"whole function, or an 'address' plus 'count' instructions (default " + DEFAULT_COUNT +
			"). A frame-relative operand the analyzer left raw ('[BP + 0xf818]' where a sibling " +
			"prints '[BP + local_7ea]') gets a trailing '; 0xf818 = local_7ea' naming the " +
			"variable at that slot, using the frame offset the function's referenced operands " +
			"establish.";
	}

	@Override
	public Map<String, Object> inputSchema() {
		return Map.of(
			"type", "object",
			"properties", Map.of(
				"function", Schemas.stringProp(
					"Whole function to disassemble: a function name or an address inside it"),
				"address", Schemas.stringProp(
					"Start address for a raw run of instructions (when no function is given)"),
				"count", Schemas.intProp("Number of instructions from 'address' (default " +
					DEFAULT_COUNT + ")")));
	}

	@Override
	public boolean isReadOnly() {
		return true;
	}

	@Override
	public McpSchema.CallToolResult execute(Map<String, Object> args, Program program) {
		String functionArg = Args.stringArg(args, "function", null);
		String addressArg = Args.stringArg(args, "address", null);
		CodeUnitFormat format = CodeUnitFormat.DEFAULT;
		StringBuilder sb = new StringBuilder();

		if (functionArg != null) {
			Function function = Locations.findFunction(program, functionArg);
			sb.append(function.getName()).append(" @ ").append(function.getEntryPoint())
					.append('\n');
			int emitted = appendFunctionInstructions(sb, program, function, format);
			if (emitted == 0) {
				sb.append("(no disassembled instructions in the ")
						.append(function.getBody().getNumAddresses())
						.append("-byte body — likely an overlay/RTLink dispatch stub; use " +
							"decompile to see the resolved code)\n");
			}
		}
		else if (addressArg != null) {
			int count = Math.min(MAX_COUNT, Math.max(1, Args.intArg(args, "count", DEFAULT_COUNT)));
			Address start = Locations.parseAddress(program, addressArg);
			// Say so when the requested address holds no code. The iterator silently begins at the
			// next instruction, which reads as "we looked here and found nothing" when in truth
			// those bytes were never examined — that misreading cost a real investigation a day.
			appendUndefinedNote(sb, program, start);
			InstructionIterator it = program.getListing().getInstructions(start, true);
			appendInstructions(sb, it, format, count);
		}
		else {
			return Results.error("Provide either 'function' or 'address'");
		}

		if (sb.length() == 0) {
			return Results.ok("No instructions (address may not be disassembled)");
		}
		return Results.ok(sb.toString());
	}

	/**
	 * Prefix a marker when {@code start} is not the first byte of an instruction, naming what is
	 * actually there and where the listing will therefore resume. Two distinct cases, both of
	 * which the bare listing hides: the address holds <em>undefined bytes</em> (never
	 * disassembled — say how many, up to the next instruction), or it is <em>offcut</em>, i.e.
	 * inside an instruction that starts earlier.
	 */
	private static void appendUndefinedNote(StringBuilder sb, Program program, Address start) {
		Listing listing = program.getListing();
		if (listing.getInstructionAt(start) != null) {
			return;
		}
		Instruction containing = listing.getInstructionContaining(start);
		if (containing != null) {
			sb.append("NOTE: ").append(start).append(" is OFFCUT — inside the instruction at ")
					.append(containing.getAddress()).append("; listing resumes at the next one.\n");
			return;
		}
		Data data = listing.getDefinedDataContaining(start);
		Instruction next = listing.getInstructionAfter(start);
		sb.append("NOTE: ").append(start).append(" holds ")
				.append(data != null ? "defined data (" + data.getDataType().getName() + ")"
						: "UNDEFINED bytes (never disassembled)");
		if (next != null) {
			sb.append("; nothing is disassembled until ").append(next.getAddress());
			try {
				sb.append(" (0x").append(Long.toHexString(next.getAddress().subtract(start)))
						.append(" bytes)");
			}
			catch (Exception spansSpaces) {
				// different address space: the byte distance is meaningless, skip it
			}
		}
		else {
			sb.append("; no further instructions in the program");
		}
		sb.append(".\nThe listing below therefore SKIPS the requested address — it is not evidence " +
			"that those bytes are not code. Use create kind=instructions to disassemble them.\n");
	}

	private void appendInstructions(StringBuilder sb, InstructionIterator it,
			CodeUnitFormat format, int max) {
		int n = 0;
		FrameHints hints = new FrameHints();
		while (it.hasNext() && n < max) {
			Instruction instruction = it.next();
			sb.append(instruction.getAddress()).append("  ")
					.append(representation(format, instruction))
					.append(hints.hint(instruction)).append('\n');
			n++;
		}
	}

	/**
	 * Names the frame variable behind a raw {@code [BP + imm]} operand. The listing only
	 * substitutes a variable name where the analyzer left a stack reference, so an
	 * address-taken slot ({@code LEA AX,[BP + 0xf818]}) prints as a bare displacement while
	 * its neighbours read {@code [BP + local_7ea]}, and pairing the two takes arithmetic the
	 * caller should not have to do. The displacement-to-frame-offset delta (the saved-BP and
	 * return-address slots) is not assumed: it is learned from any operand in the same
	 * function that has both a displacement and a stack reference, so the hint is exact for
	 * that function or absent.
	 */
	private static final class FrameHints {

		private Function function;
		private Register register;
		private Long delta;

		String hint(Instruction instruction) {
			Function here = instruction.getProgram().getFunctionManager()
					.getFunctionContaining(instruction.getAddress());
			if (here == null) {
				return "";
			}
			if (here != function) {
				function = here;
				learn();
			}
			if (delta == null) {
				return "";
			}
			StringBuilder sb = new StringBuilder();
			for (int i = 0; i < instruction.getNumOperands(); i++) {
				if (hasStackReference(instruction, i)) {
					continue;
				}
				Scalar displacement = displacement(instruction, i);
				if (displacement == null) {
					continue;
				}
				int offset = (int) (displacement.getSignedValue() + delta);
				Variable variable = function.getStackFrame().getVariableContaining(offset);
				if (variable == null) {
					continue;
				}
				sb.append(sb.isEmpty() ? "  ; " : ", ").append(displacement).append(" = ")
						.append(variable.getName());
				int into = offset - variable.getStackOffset();
				if (into != 0) {
					sb.append("+0x").append(Integer.toHexString(into));
				}
			}
			return sb.toString();
		}

		/** Find one operand with both a frame displacement and a stack reference; it fixes
		 * the register and the delta for the whole function. */
		private void learn() {
			register = null;
			delta = null;
			InstructionIterator it = function.getProgram().getListing()
					.getInstructions(function.getBody(), true);
			while (it.hasNext()) {
				Instruction instruction = it.next();
				for (int i = 0; i < instruction.getNumOperands(); i++) {
					Register base = baseRegister(instruction, i);
					Scalar displacement = base == null ? null : scalar(instruction, i);
					if (displacement == null) {
						continue;
					}
					for (Reference reference : instruction.getOperandReferences(i)) {
						if (reference instanceof StackReference stack) {
							register = base;
							delta = stack.getStackOffset() - displacement.getSignedValue();
							return;
						}
					}
				}
			}
		}

		private Scalar displacement(Instruction instruction, int operand) {
			Register base = baseRegister(instruction, operand);
			return base != null && base.equals(register) ? scalar(instruction, operand) : null;
		}

		/** The single register of an operand shaped {@code [reg + imm]}, else null. */
		private static Register baseRegister(Instruction instruction, int operand) {
			Register only = null;
			for (Object object : instruction.getOpObjects(operand)) {
				if (object instanceof Register r) {
					if (only != null) {
						return null;
					}
					only = r;
				}
			}
			return only;
		}

		private static Scalar scalar(Instruction instruction, int operand) {
			Scalar only = null;
			for (Object object : instruction.getOpObjects(operand)) {
				if (object instanceof Scalar s) {
					if (only != null) {
						return null;
					}
					only = s;
				}
			}
			return only;
		}

		private static boolean hasStackReference(Instruction instruction, int operand) {
			for (Reference reference : instruction.getOperandReferences(operand)) {
				if (reference.isStackReference()) {
					return true;
				}
			}
			return false;
		}
	}

	/**
	 * Mnemonic and operands, with every separator the language defines.
	 *
	 * <p>Not {@code CodeUnitFormat.getRepresentationString}: that walks operands {@code 0..n-1}
	 * and emits only the separator <em>before</em> each one past the first, so it drops both the
	 * leading separator and the trailing one at index {@code n} &mdash; the {@code )} of a
	 * {@code disp(reg)} operand, for instance, which SLEIGH holds as the separator after the last
	 * operand. The loop below is {@code Instruction.toString}'s, which gets this right, but it
	 * keeps the format's operand rendering so symbols still resolve to their names.
	 *
	 * <p><b>Do not "simplify" this back to {@code getRepresentationString}.</b> It is a core
	 * defect, not a quirk of one language: stock RISC-V renders every {@code amo*} in the A
	 * extension as {@code amoadd.w a0,a1,(a2}, and m68k's {@code cas2} has the same shape
	 * (confirmed in the 12.1.3 source by {@code dailydriver}, which is preparing a core fix).
	 * This stays even once that lands &mdash; the extension also runs against stock Ghidra,
	 * where it will not be fixed.
	 */
	private static String representation(CodeUnitFormat format, Instruction instruction) {
		StringBuilder text = new StringBuilder(format.getMnemonicRepresentation(instruction));
		int operands = instruction.getNumOperands();
		String separator = instruction.getSeparator(0);
		if (separator != null || operands != 0) {
			text.append(' ');
		}
		appendSeparator(text, separator);
		for (int i = 0; i < operands; i++) {
			text.append(format.getOperandRepresentationString(instruction, i));
			appendSeparator(text, instruction.getSeparator(i + 1));
		}
		return text.toString();
	}

	private static void appendSeparator(StringBuilder text, String separator) {
		if (separator != null) {
			text.append(separator);
		}
	}

	/**
	 * Walk instructions from the entry point, stopping when we leave the function.
	 * (Iterating {@code getInstructions(function.getBody())} can come back empty in
	 * 16-bit segmented programs, so anchor on the entry point instead.)
	 */
	private int appendFunctionInstructions(StringBuilder sb, Program program, Function function,
			CodeUnitFormat format) {
		InstructionIterator it = program.getListing().getInstructions(function.getEntryPoint(), true);
		int emitted = 0;
		FrameHints hints = new FrameHints();
		while (it.hasNext() && emitted < MAX_COUNT * 4) {
			Instruction instruction = it.next();
			if (program.getFunctionManager()
					.getFunctionContaining(instruction.getAddress()) != function) {
				break;
			}
			sb.append(instruction.getAddress()).append("  ")
					.append(representation(format, instruction))
					.append(hints.hint(instruction)).append('\n');
			emitted++;
		}
		return emitted;
	}
}
