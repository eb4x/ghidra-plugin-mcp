package ebbex.ghidramcpserver.tools;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.util.Map;

import org.junit.Test;

import ebbex.ghidramcpserver.RealModeProgramTest;
import ebbex.ghidramcpserver.util.Decompilers;
import ebbex.ghidramcpserver.util.Variables;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.data.WordDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.LocalVariableImpl;
import ghidra.program.model.symbol.SourceType;

/**
 * Retyping a stack local to something larger than the slot the decompiler split it into:
 * the error maps each overlapped local to its offset in the new type, and
 * replace_overlapping=true removes them and applies the type.
 */
public class SetDataTypeOverlapTest extends RealModeProgramTest {

	private final SetDataTypeTool setDataType = new SetDataTypeTool(new Decompilers(1));

	private Function functionWithSplitLocals() throws Exception {
		Function f = builder.createEmptyFunction("f", "1000:0010", 0x20, VoidDataType.dataType);
		int tx = program.startTransaction("locals");
		try {
			f.addLocalVariable(new LocalVariableImpl("lo", WordDataType.dataType, -0x10, program),
				SourceType.USER_DEFINED);
			f.addLocalVariable(new LocalVariableImpl("hi", WordDataType.dataType, -0xe, program),
				SourceType.USER_DEFINED);
		}
		finally {
			program.endTransaction(tx, true);
		}
		return f;
	}

	@Test
	public void conflictNamesTheOverlappedLocalAndItsOffset() throws Exception {
		Function f = functionWithSplitLocals();
		String out = error(setDataType, Map.of("kind", "local_variable", "function", "f",
			"variable_name", "lo", "type", "long"));
		assertTrue(out, out.contains("hi (word @ Stack[-0xe]:2 = +0x2 in the new type)"));
		assertTrue(out, out.contains("replace_overlapping=true"));
		assertEquals("nothing changed", "word", Variables.findDbVariable(f, "lo").getDataType().getName());
	}

	@Test
	public void replaceOverlappingRemovesThemAndAppliesTheType() throws Exception {
		Function f = functionWithSplitLocals();
		String out = ok(setDataType, Map.of("kind", "local_variable", "function", "f",
			"variable_name", "lo", "type", "long", "replace_overlapping", true));
		assertTrue(out, out.contains("Set type of lo to long (4 bytes)"));
		assertTrue(out, out.contains("Removed 1 overlapping variable(s): hi (word @ Stack[-0xe]:2 = +0x2 in the new type)"));
		assertEquals("long", Variables.findDbVariable(f, "lo").getDataType().getName());
		assertNull(Variables.findDbVariable(f, "hi"));
	}
}
