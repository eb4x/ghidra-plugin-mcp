package ebbex.ghidramcpserver.tools;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.util.List;
import java.util.Map;

import org.junit.Test;

import ebbex.ghidramcpserver.RealModeProgramTest;
import ebbex.ghidramcpserver.util.Decompilers;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.listing.Function;

/** A void return given with a storage means "no return value"; the storage is ignored. */
public class VoidReturnStorageTest extends RealModeProgramTest {

	private final SetFunctionSignatureTool setSignature =
		new SetFunctionSignatureTool(new Decompilers(1));

	@Test
	public void voidReturnWithStorageIsAccepted() throws Exception {
		Function f = builder.createEmptyFunction("f", "1000:0500", 0x10, IntegerDataType.dataType);
		String out = ok(setSignature, Map.of("function", "f",
			"parameters", List.of(Map.of("name", "object_id", "type", "int", "storage", "AX")),
			"return", Map.of("type", "void", "storage", "AX")));
		assertTrue(out, out.contains("object_id@AX:2:int"));
		assertTrue(out, out.contains("-> void (storage 'AX' ignored)"));
		assertEquals("void", f.getReturnType().getName());
		assertEquals(1, f.getParameterCount());
	}
}
