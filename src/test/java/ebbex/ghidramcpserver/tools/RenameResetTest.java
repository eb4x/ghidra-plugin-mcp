package ebbex.ghidramcpserver.tools;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.util.Map;

import org.junit.Test;

import ebbex.ghidramcpserver.RealModeProgramTest;
import ebbex.ghidramcpserver.util.Decompilers;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.SourceType;

/**
 * reset=true returns a function to Ghidra's default name — a thunk then follows its target —
 * and removes a user label so the dynamic one shows again.
 */
public class RenameResetTest extends RealModeProgramTest {

	private final RenameTool rename = new RenameTool(new Decompilers(1));

	@Test
	public void functionGoesBackToItsDefaultName() throws Exception {
		Function f = builder.createEmptyFunction("madspack_read", "1000:0300", 0x10,
			VoidDataType.dataType);
		String out = ok(rename, Map.of("kind", "function", "function", "1000:0300",
			"reset", true));
		assertTrue(out, out.contains("Reset function madspack_read @ 1000:0300 to its default " +
			"name FUN_1000_0300"));
		assertEquals(SourceType.DEFAULT, f.getSymbol().getSource());
		String again = ok(rename, Map.of("kind", "function", "function", "1000:0300",
			"reset", true));
		assertTrue(again, again.contains("already has its default name"));
	}

	@Test
	public void thunkFollowsItsTargetAgain() throws Exception {
		builder.createEmptyFunction("madspack_read", "1000:0300", 0x10, VoidDataType.dataType);
		Function gate = builder.createEmptyFunction("gate_renamed", "1000:0400", 0x10,
			VoidDataType.dataType);
		int tx = program.startTransaction("thunk");
		try {
			gate.setThunkedFunction(
				program.getFunctionManager().getFunctionAt(addr("1000:0300")));
		}
		finally {
			program.endTransaction(tx, true);
		}
		String out = ok(rename, Map.of("kind", "function", "function", "1000:0400",
			"reset", true));
		assertTrue(out, out.contains("to its default name madspack_read"));
		assertTrue(out, out.contains("thunk follows its target"));
		assertEquals("madspack_read", gate.getName());
	}

	@Test
	public void labelIsRemovedAndNewNameIsNotRequired() throws Exception {
		builder.createLabel("1000:0500", "my_label");
		String out = ok(rename, Map.of("kind", "label", "address", "1000:0500", "reset", true));
		assertTrue(out, out.contains("Removed label my_label @ 1000:0500"));
		assertTrue(out, out.contains("no default label shows"));
		assertNull(program.getSymbolTable().getPrimarySymbol(addr("1000:0500")));
		String without = error(rename, Map.of("kind", "label", "address", "1000:0500"));
		assertTrue(without, without.contains("new_name is required (or reset=true"));
	}

	private Address addr(String s) {
		return program.getAddressFactory().getAddress(s);
	}
}
