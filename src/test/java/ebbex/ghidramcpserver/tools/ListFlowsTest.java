package ebbex.ghidramcpserver.tools;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.math.BigInteger;
import java.util.List;
import java.util.Map;

import org.junit.Before;
import org.junit.Test;

import ebbex.ghidramcpserver.RealModeProgramTest;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;

/**
 * {@code list kind=flows}: every jump and call with its bytes, the assumed CS, Ghidra's target as
 * seg:off and linear, the distance to the next instruction and the CS-window relation; the filter
 * selects an encoding; {@code summary=true} counts instead of listing.
 */
public class ListFlowsTest extends RealModeProgramTest {

	private final ListTool list = new ListTool(null);

	@Before
	public void layOutBranches() throws Exception {
		// 1000:0000  e8 10 00     CALL rel16 +0x10   -> 1000:0013
		// 1000:0003  eb 05        JMP  rel8  +5      -> 1000:000a
		// 1000:0005  0f 84 00 10  JZ   rel16 +0x1000 -> 1000:1009
		// 1000:0009  c3           RET  (terminal, not a flow line)
		int tx = program.startTransaction("cs");
		try {
			Register cs = program.getRegister("CS");
			Address start = program.getAddressFactory().getAddress("1000:0000");
			Address end = program.getAddressFactory().getAddress("1000:0fff");
			program.getProgramContext().setValue(cs, start, end, BigInteger.valueOf(0x1000));
		}
		finally {
			program.endTransaction(tx, true);
		}
		builder.setBytes("1000:0000", "e8 10 00 eb 05 0f 84 00 10 c3", true);
	}

	@Test
	public void everyBranchGetsBytesContextTargetAndDistance() throws Exception {
		String text = ok(list, Map.of("kind", "flows"));
		List<String> lines = List.of(text.split("\n"));
		assertEquals(text, "(3 total)", lines.get(3));
		assertEquals("1000:0000  e8 10 00  CALL  [call]  CS=0x1000  -> 1000:0013 lin 0x10013  " +
			"d=+0x10  in CS window", lines.get(0));
		assertEquals("1000:0003  eb 05  JMP  [jump]  CS=0x1000  -> 1000:000a lin 0x1000a  " +
			"d=+0x5  in CS window", lines.get(1));
		assertEquals("1000:0005  0f 84 00 10  JZ  [jump, cond]  CS=0x1000  -> 1000:1009 " +
			"lin 0x11009  d=+0x1000  in CS window", lines.get(2));
		assertFalse(text.contains("RET"));
	}

	@Test
	public void theFilterSelectsAnEncodingAndSummaryCounts() throws Exception {
		String rel16Jcc = ok(list, Map.of("kind", "flows", "filter", "0f 8"));
		assertTrue(rel16Jcc, rel16Jcc.startsWith("1000:0005  0f 84 00 10  JZ"));
		assertTrue(rel16Jcc, rel16Jcc.endsWith("(1 total)"));

		String summary = ok(list, Map.of("kind", "flows", "summary", true));
		assertTrue(summary, summary.contains("      1  CALL  3 bytes  in CS window\n"));
		assertTrue(summary, summary.contains("      1  JZ  4 bytes  in CS window\n"));
		assertTrue(summary, summary.endsWith("(3 flows in 3 groups; summary=false lists them)"));

		String calls = ok(list, Map.of("kind", "flows", "summary", true, "filter", "call"));
		assertTrue(calls, calls.endsWith("(1 flows in 1 groups; summary=false lists them)"));
	}

	@Test
	public void contextNamesAnotherRegisterAndIsRefusedForOtherKinds() throws Exception {
		String ds = ok(list, Map.of("kind", "flows", "context", "DS", "limit", 1));
		assertTrue(ds, ds.startsWith("1000:0000  e8 10 00  CALL  [call]  -> 1000:0013 lin 0x10013  " +
			"d=+0x10  same segment"));
		assertTrue(error(list, Map.of("kind", "flows", "context", "XYZ")).contains("XYZ"));
		assertTrue(error(list, Map.of("kind", "functions", "summary", true))
				.contains("apply to kind=flows"));
	}
}
