package ebbex.ghidramcpserver.tools;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.util.Iterator;
import java.util.List;

import org.junit.Test;

import ebbex.ghidramcpserver.RealModeProgramTest;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.Varnode;
import ghidra.util.task.TaskMonitor;

/**
 * A local whose address escapes gets an entry-value input from the decompiler although no
 * prototype could declare it, so it is not reported. (The register case, helper's in_EDI, is
 * the smoke test's.)
 */
public class UndeclaredInputsTest extends RealModeProgramTest {

	@Test
	public void aFrameLocalWithAnInputInstanceIsNotReported() throws Exception {
		builder.setBytes("1000:0200", "c3", true);
		builder.setBytes("1000:0100", """
			55 8b ec 83 ec 02 8d 46 fe 50 e8 f3 00 83 c4 02
			8b 46 fe 03 c2 8b e5 5d c3""".replaceAll("\\s+", " "), true);
		builder.createFunction("1000:0200");
		Function f = builder.createFunction("1000:0100");

		DecompInterface decompiler = new DecompInterface();
		try {
			decompiler.openProgram(program);
			DecompileResults results = decompiler.decompileFunction(f, 30, TaskMonitor.DUMMY);
			assertTrue(results.getErrorMessage(), results.decompileCompleted());
			assertTrue("precondition: the escaped local has an input instance",
				frameLocalHasInput(results));

			DecompileTool.IrregularInputs inputs = DecompileTool.irregularInputs(results);
			assertEquals(List.of(), inputs.args());
			assertEquals(List.of(), inputs.flags());
		}
		finally {
			decompiler.dispose();
		}
	}

	private static boolean frameLocalHasInput(DecompileResults results) {
		Iterator<HighSymbol> symbols = results.getHighFunction().getLocalSymbolMap().getSymbols();
		while (symbols.hasNext()) {
			HighSymbol symbol = symbols.next();
			if (!symbol.getStorage().isStackStorage() || symbol.getStorage().getStackOffset() >= 0 ||
				symbol.getHighVariable() == null) {
				continue;
			}
			for (Varnode instance : symbol.getHighVariable().getInstances()) {
				if (instance.isInput()) {
					return true;
				}
			}
		}
		return false;
	}
}
