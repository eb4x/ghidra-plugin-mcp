package ebbex.ghidramcpserver.util;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.util.Map;

import org.junit.Test;

import ebbex.ghidramcpserver.RealModeProgramTest;
import ebbex.ghidramcpserver.tools.SetDataTypeTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.symbol.SourceType;

/**
 * Ghidra nests transactions per program: an edit made while another transaction is open (the
 * GUI's auto-analysis, started by an earlier edit) is an entry inside it, and rolling that entry
 * back aborts the whole enclosing transaction when it ends. A failing edit must therefore be kept
 * and reported when nested, and rolled back only when it is a transaction of its own.
 */
public class TransactionNestingTest extends RealModeProgramTest {

	private final SetDataTypeTool setDataType = new SetDataTypeTool(new Decompilers(1));

	/** Outside the program's memory, so createData throws inside the transaction body. */
	private static final Map<String, Object> FAILING_EDIT =
		Map.of("kind", "data", "address", "2000:0000", "type", "long");

	@Test
	public void failureInsideAnotherTransactionIsKeptAndSaysSo() throws Exception {
		Address kept = program.getAddressFactory().getAddress("1000:0100");
		int outer = program.startTransaction("Auto Analysis");
		String out;
		try {
			program.getSymbolTable().createLabel(kept, "kept_by_outer", SourceType.USER_DEFINED);
			out = error(setDataType, FAILING_EDIT);
		}
		finally {
			program.endTransaction(outer, true);
		}
		assertTrue(out, out.contains("Set data type failed:"));
		assertTrue(out, out.contains("NOT rolled back"));
		assertTrue(out, out.contains("'Auto Analysis'"));
		assertNull(program.getCurrentTransactionInfo());
		assertTrue("the enclosing transaction's own work must survive the nested failure",
			program.getSymbolTable().getSymbols("kept_by_outer").hasNext());
	}

	@Test
	public void failureOnItsOwnIsRolledBackWithoutTheNestingNote() throws Exception {
		String out = error(setDataType, FAILING_EDIT);
		assertTrue(out, out.contains("Set data type failed:"));
		assertFalse(out, out.contains("NOT rolled back"));
		assertNull(program.getCurrentTransactionInfo());
	}
}
