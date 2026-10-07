package ebbex.ghidramcpserver.tools;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.util.Map;

import org.junit.Test;

import ebbex.ghidramcpserver.RealModeProgramTest;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;

/**
 * Undefined filler in a non-packed struct is one component per byte, so the component at the
 * edited offset always says "1 byte"; the echo must count what the new field actually takes.
 */
public class SetFieldCountTest extends RealModeProgramTest {

	private final ManageTypesTool manageTypes = new ManageTypesTool();

	private Structure emptyStruct(int size) {
		int tx = program.startTransaction("struct");
		try {
			return (Structure) program.getDataTypeManager().addDataType(
				new StructureDataType("Handle", size), DataTypeConflictHandler.REPLACE_HANDLER);
		}
		finally {
			program.endTransaction(tx, true);
		}
	}

	@Test
	public void countsEveryUndefinedByteTheFieldConsumes() throws Exception {
		Structure s = emptyStruct(0x20);
		String out = ok(manageTypes, Map.of("op", "set_field", "name", "Handle",
			"offset", "0xc", "type", "long", "new_name", "size"));
		assertTrue(out, out.contains("replacing 4 undefined bytes at +0xc."));
		assertEquals(0x20, s.getLength());
		assertEquals("size", s.getComponentContaining(0xc).getFieldName());
	}

	@Test
	public void saysWhenTheFieldGrowsTheStruct() throws Exception {
		Structure s = emptyStruct(0x20);
		String out = ok(manageTypes, Map.of("op", "set_field", "name", "Handle",
			"offset", "0x1e", "type", "long"));
		assertTrue(out, out.contains("replacing 2 undefined bytes at +0x1e and growing the " +
			"struct by 2 bytes."));
		assertEquals(0x22, s.getLength());
	}
}
