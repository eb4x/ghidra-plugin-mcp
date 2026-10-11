package ebbex.ghidramcpserver.tools;

import java.math.BigInteger;
import java.util.Iterator;
import java.util.NoSuchElementException;

import ebbex.ghidramcpserver.util.Locations;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.SegmentedAddress;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.ProgramContext;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.symbol.FlowType;

/**
 * The rows of {@code list kind=flows}: every jump and call with its encoding, the assumed
 * segment-register context at its address, and the flow target Ghidra currently holds for it,
 * as both {@code seg:off} and linear. The point is to size a branch-encoding question (how many
 * rel16 branches land outside their CS window?) in one call instead of a read_bytes and an
 * inspect per hit: the bytes tell the width, the context value tells the window, the target
 * tells what the decompiler sees today, and the distance {@code d} to the next instruction is
 * what the encoded immediate should equal when the target was computed without wrapping.
 */
final class FlowLines {

	/** A listing line and the group it counts under in {@code summary=true}. */
	record Row(String line, String group) {
	}

	private FlowLines() {
	}

	static Iterator<Row> rows(Program program, Address from, Address to, Register context) {
		Listing listing = program.getListing();
		InstructionIterator instructions = from == null && to == null
				? listing.getInstructions(true)
				: listing.getInstructions(Locations.scope(program, from, to), true);
		ProgramContext programContext = program.getProgramContext();
		return new Iterator<>() {
			private Row pending;

			@Override
			public boolean hasNext() {
				while (pending == null && instructions.hasNext()) {
					Instruction instruction = instructions.next();
					FlowType flow = instruction.getFlowType();
					if (flow.isJump() || flow.isCall()) {
						pending = row(programContext, context, instruction);
					}
				}
				return pending != null;
			}

			@Override
			public Row next() {
				if (!hasNext()) {
					throw new NoSuchElementException();
				}
				Row row = pending;
				pending = null;
				return row;
			}
		};
	}

	private static Row row(ProgramContext programContext, Register context,
			Instruction instruction) {
		FlowType flow = instruction.getFlowType();
		String kind = (flow.isCall() ? "call" : "jump") + (flow.isConditional() ? ", cond" : "") +
			(flow.isComputed() ? ", computed" : "");
		BigInteger contextValue = context == null ? null
				: programContext.getValue(context, instruction.getAddress(), false);
		String contextText = contextValue == null ? ""
				: "  " + context.getName() + "=0x" + contextValue.toString(16);

		Address[] flows = instruction.getFlows();
		String target;
		String relation;
		if (flows.length == 0) {
			target = "  -> (no target)";
			relation = "no target";
		}
		else {
			Address next = instruction.getMaxAddress().next();
			long distance = next == null ? 0 : linear(flows[0]) - linear(next);
			relation = relation(instruction.getAddress(), flows[0], contextValue) +
				(next != null && (linear(next) >>> 16) != (linear(flows[0]) >>> 16)
						? ", crosses 64K page" : "");
			target = "  -> " + flows[0] + " lin 0x" + Long.toHexString(linear(flows[0])) +
				(next == null ? "" : "  d=" + signedHex(distance)) +
				(flows.length > 1 ? "  (+" + (flows.length - 1) + " more)" : "") + "  " + relation;
		}
		String mnemonic = instruction.getMnemonicString();
		String line = instruction.getAddress() + "  " + hex(instruction) + "  " + mnemonic + "  [" +
			kind + "]" + contextText + target;
		String group = mnemonic + "  " + instruction.getLength() + " bytes  " + relation;
		return new Row(line, group);
	}

	/**
	 * Where the target lies relative to the branch: inside the 64K window the assumed CS
	 * value spans, or outside it; without a context value, whether it shares the branch's
	 * segment frame. The caller appends ", crosses 64K page" when the target's linear 64K
	 * page differs from the next instruction's: that is where a 16-bit offset computed from
	 * the wrong base lands in another page, the other half of the rel16 question.
	 */
	private static String relation(Address at, Address target, BigInteger contextValue) {
		if (contextValue != null) {
			long base = contextValue.longValue() << 4;
			long linear = linear(target);
			return linear >= base && linear <= base + 0xFFFF ? "in CS window" : "outside CS window";
		}
		if (at instanceof SegmentedAddress here && target instanceof SegmentedAddress there) {
			return here.getSegment() == there.getSegment() ? "same segment" : "other segment";
		}
		return at.getAddressSpace().equals(target.getAddressSpace()) ? "same space" : "other space";
	}

	/** The flat address: a segmented address's offset is already linear. */
	private static long linear(Address address) {
		return address.getOffset();
	}

	private static String signedHex(long value) {
		return (value < 0 ? "-0x" : "+0x") + Long.toHexString(Math.abs(value));
	}

	private static String hex(Instruction instruction) {
		try {
			StringBuilder sb = new StringBuilder();
			for (byte b : instruction.getBytes()) {
				if (!sb.isEmpty()) {
					sb.append(' ');
				}
				sb.append(String.format("%02x", b & 0xff));
			}
			return sb.toString();
		}
		catch (MemoryAccessException e) {
			return "??";
		}
	}
}
