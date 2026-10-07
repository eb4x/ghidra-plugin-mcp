package ebbex.ghidramcpserver.tools;

import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.util.Map;

import org.junit.Test;

import ebbex.ghidramcpserver.RealModeProgramTest;
import ebbex.ghidramcpserver.util.Variables;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.data.WordDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.LocalVariableImpl;
import ghidra.program.model.symbol.SourceType;

/**
 * clear kind=local_variable by first-use address: the handle that survives the decompiler
 * renumbering a type-locked symbol's iVar-style name.
 */
public class ClearByPcTest extends RealModeProgramTest {

	private final ClearTool clear = new ClearTool();
	private final InspectTool inspect = new InspectTool();

	private Function functionWithRegisterLocals() throws Exception {
		Function f = builder.createEmptyFunction("f", "1000:0010", 0x40, VoidDataType.dataType);
		int tx = program.startTransaction("locals");
		try {
			f.addLocalVariable(new LocalVariableImpl("iVar7", 0x20, WordDataType.dataType,
				program.getRegister("DX"), program), SourceType.USER_DEFINED);
			f.addLocalVariable(new LocalVariableImpl("iVar8", 0x20, WordDataType.dataType,
				program.getRegister("AX"), program), SourceType.USER_DEFINED);
			f.addLocalVariable(new LocalVariableImpl("counter", 0x30, WordDataType.dataType,
				program.getRegister("CX"), program), SourceType.USER_DEFINED);
		}
		finally {
			program.endTransaction(tx, true);
		}
		return f;
	}

	@Test
	public void clearsTheOneLocalFirstUsedAtThePc() throws Exception {
		Function f = functionWithRegisterLocals();
		String out = ok(clear, Map.of("kind", "local_variable", "function", "f",
			"pc", "1000:0040"));
		assertTrue(out, out.contains("Deleted local variable counter (word @ CX:2) first used " +
			"at 1000:0040"));
		assertNull(Variables.findDbVariable(f, "counter"));
	}

	@Test
	public void severalAtOnePcNeedTheName() throws Exception {
		Function f = functionWithRegisterLocals();
		String out = error(clear, Map.of("kind", "local_variable", "function", "f",
			"pc", "1000:0030"));
		assertTrue(out, out.contains("2 locals have their first use at 1000:0030"));
		assertTrue(out, out.contains("iVar7 (word @ DX:2, first use 1000:0030)"));
		String picked = ok(clear, Map.of("kind", "local_variable", "function", "f",
			"pc", "1000:0030", "variable_name", "iVar7"));
		assertTrue(picked, picked.contains("Deleted local variable iVar7"));
		assertNull(Variables.findDbVariable(f, "iVar7"));
	}

	@Test
	public void nothingAtThePcListsTheStoredLocals() throws Exception {
		functionWithRegisterLocals();
		String out = error(clear, Map.of("kind", "local_variable", "function", "f",
			"pc", "1000:0012"));
		assertTrue(out, out.contains("No local variable of f has its first use at 1000:0012"));
		assertTrue(out, out.contains("counter (CX:2, first use 1000:0040)"));
	}

	@Test
	public void inspectPrintsFirstUseAsAnAddress() throws Exception {
		functionWithRegisterLocals();
		String out = ok(inspect, Map.of("location", "1000:0010"));
		assertTrue(out, out.contains("local  counter  word  CX:2  first_use=1000:0040  USER_DEFINED"));
	}
}
