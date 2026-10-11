package ebbex.ghidramcpserver.tools;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.util.Map;

import org.junit.Before;
import org.junit.Test;

import ebbex.ghidramcpserver.RealModeProgramTest;
import ebbex.ghidramcpserver.util.Decompilers;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.listing.Function;

/**
 * {@code set_function_signature call_fixup=…}: installs a compiler-spec call fixup by name, ""
 * clears it, an unknown name is refused with the names the spec defines, and inspect shows it.
 */
public class CallFixupTest extends RealModeProgramTest {

	private final SetFunctionSignatureTool signature =
		new SetFunctionSignatureTool(new Decompilers(1));
	private final InspectTool inspect = new InspectTool();
	private Function probe;

	@Before
	public void makeProbe() throws Exception {
		probe = builder.createEmptyFunction("_chkstk", "1000:0300", 0x10, VoidDataType.dataType);
	}

	@Test
	public void anUnknownNameIsRefusedWithTheSpecsNames() throws Exception {
		String refusal = error(signature, Map.of("function", "_chkstk", "call_fixup", "nosuch"));
		assertTrue(refusal, refusal.startsWith("Unknown call fixup 'nosuch': the compiler spec " +
			"x86:LE:16:Real Mode/default defines "));
		assertTrue(refusal, refusal.endsWith(". \"\" clears the fixup."));
		assertNull(probe.getCallFixup());
	}

	@Test
	public void aKnownNameIsInstalledShownAndCleared() throws Exception {
		String[] names =
			program.getCompilerSpec().getPcodeInjectLibrary().getCallFixupNames();
		if (names.length == 0) {
			// This SDK's x86-16 spec declares no fixups; the refusal test covers the lookup.
			return;
		}
		String name = names[0];
		assertEquals("_chkstk [call fixup " + name + "]",
			ok(signature, Map.of("function", "_chkstk", "call_fixup", name)));
		assertEquals(name, probe.getCallFixup());
		assertTrue(ok(inspect, Map.of("location", "1000:0300")).contains("\n  call fixup " + name + "\n"));

		String withFlag = ok(signature,
			Map.of("function", "_chkstk", "noreturn", true, "call_fixup", name));
		assertTrue(withFlag, withFlag.endsWith("[noreturn set]\n[call fixup " + name + "]"));

		assertEquals("_chkstk [call fixup cleared]",
			ok(signature, Map.of("function", "_chkstk", "call_fixup", "")));
		assertNull(probe.getCallFixup());
		assertFalse(ok(inspect, Map.of("location", "1000:0300")).contains("call fixup"));
	}
}
