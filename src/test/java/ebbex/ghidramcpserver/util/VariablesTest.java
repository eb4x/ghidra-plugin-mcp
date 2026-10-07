package ebbex.ghidramcpserver.util;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.util.List;
import java.util.Map;

import org.junit.Test;

import ebbex.ghidramcpserver.RealModeProgramTest;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.data.WordDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.LocalVariableImpl;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.symbol.SourceType;

/** The database-side helpers behind the pc handle: first use, overlap, snapshots, names. */
public class VariablesTest extends RealModeProgramTest {

	private Function functionWithRegisterLocals() throws Exception {
		Function f = builder.createEmptyFunction("f", "1000:0010", 0x40, VoidDataType.dataType);
		int tx = program.startTransaction("locals");
		try {
			f.addLocalVariable(new LocalVariableImpl("dx_half", 0x20, WordDataType.dataType,
				program.getRegister("DX"), program), SourceType.USER_DEFINED);
			f.addLocalVariable(new LocalVariableImpl("ax_half", 0x20, WordDataType.dataType,
				program.getRegister("AX"), program), SourceType.USER_DEFINED);
			f.addLocalVariable(new LocalVariableImpl("later_dx", 0x30, WordDataType.dataType,
				program.getRegister("DX"), program), SourceType.USER_DEFINED);
		}
		finally {
			program.endTransaction(tx, true);
		}
		return f;
	}

	@Test
	public void firstUseIsAnAddress() throws Exception {
		Function f = functionWithRegisterLocals();
		Variable dx = findDb(f, "dx_half");
		assertEquals("1000:0030", Variables.firstUse(f, dx));
	}

	@Test
	public void intersectingIsKeyedByFirstUseLikeGhidrasConflictCheck() throws Exception {
		Function f = functionWithRegisterLocals();
		// A 4-byte DX:AX result at this first use covers both halves defined by the same
		// instruction; the DX used later in the function is a different variable and stays.
		VariableStorage dxax = new VariableStorage(program, program.getRegister("DX"),
			program.getRegister("AX"));
		List<Variable> hits = Variables.intersecting(f, dxax,
			program.getAddressFactory().getAddress("1000:0030"), null);
		String described = Variables.describe(f, hits);
		assertEquals(described, 2, hits.size());
		assertTrue(described, described.contains("dx_half (word @ DX:2, first use 1000:0030)"));
		assertTrue(described, described.contains("ax_half"));
		assertFalse(described, described.contains("later_dx"));
		// The variable with exactly this storage at this first use is reused, not removed.
		VariableStorage dx = new VariableStorage(program, program.getRegister("DX"));
		assertTrue(Variables.intersecting(f, dx,
			program.getAddressFactory().getAddress("1000:0030"), null).isEmpty());
	}

	@Test
	public void storageSpellingsMatchTheDumpAndTheRegisterPair() {
		assertTrue(Variables.storageMatches("DX:2,AX:2", "DX:AX"));
		assertTrue(Variables.storageMatches("DX:2,AX:2", "dx:2,ax:2"));
		assertTrue(Variables.storageMatches("DX:2,AX:2", "DX, AX"));
		assertTrue(Variables.storageMatches("AX:2", "ax"));
		assertTrue(Variables.storageMatches("Stack[-0x10]:2", "Stack[-0x10]"));
		assertFalse(Variables.storageMatches("DX:2,AX:2", "DX"));
		assertFalse(Variables.storageMatches("AX:2", "DX"));
	}

	@Test
	public void snapshotNamesWhatACommitRemoved() throws Exception {
		Function f = functionWithRegisterLocals();
		Map<Long, String> before = Variables.snapshot(f);
		int tx = program.startTransaction("remove");
		try {
			f.removeVariable(findDb(f, "ax_half"));
		}
		finally {
			program.endTransaction(tx, true);
		}
		List<String> removed = Variables.removedSince(f, before);
		assertEquals(removed.toString(), 1, removed.size());
		assertTrue(removed.get(0), removed.get(0).startsWith("ax_half (word @ AX:2"));
	}

	@Test
	public void autoNamesAreTheDecompilersOwn() {
		assertTrue(Variables.isAutoName("iVar7"));
		assertTrue(Variables.isAutoName("pcVar3"));
		assertTrue(Variables.isAutoName("local_42e"));
		assertTrue(Variables.isAutoName("in_AX"));
		assertFalse(Variables.isAutoName("dest"));
		assertFalse(Variables.isAutoName("stream_buffer"));
	}

	private static Variable findDb(Function f, String name) {
		Variable v = Variables.findDbVariable(f, name);
		if (v == null) {
			throw new AssertionError("no variable " + name);
		}
		return v;
	}
}
