package ebbex.ghidramcpserver.tools;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.util.Map;

import org.junit.Test;

import ebbex.ghidramcpserver.RealModeProgramTest;
import ebbex.ghidramcpserver.util.Decompilers;
import ghidra.program.model.address.Address;

/**
 * Ghidra's default DAT_ labels are dynamic and exist only at referenced addresses, so defined
 * data nothing points at has no symbol. rename kind=data names it anyway; kind=label keeps
 * pointing at create kind=label, since a label at a bare address is more often a typo.
 */
public class RenameDataTest extends RealModeProgramTest {

	private final SetDataTypeTool setDataType = new SetDataTypeTool(new Decompilers(1));
	private final RenameTool rename = new RenameTool(new Decompilers(1));

	@Test
	public void renamingUnreferencedDataCreatesItsLabel() throws Exception {
		builder.setBytes("1000:0200", "41 42 43 00");
		ok(setDataType, Map.of("kind", "data", "address", "1000:0200", "type", "char[4]"));
		Address address = program.getAddressFactory().getAddress("1000:0200");
		assertEquals("no default label without a reference", null,
			program.getSymbolTable().getPrimarySymbol(address));

		String out = ok(rename, Map.of("kind", "data", "address", "1000:0200",
			"new_name", "s_abc"));
		assertTrue(out, out.contains("Named the data at 1000:0200 s_abc"));
		assertEquals("s_abc", program.getSymbolTable().getPrimarySymbol(address).getName());

		String again = ok(rename, Map.of("kind", "data", "address", "1000:0200",
			"new_name", "s_extension"));
		assertTrue(again, again.contains("Renamed s_abc -> s_extension"));
	}

	@Test
	public void renamingALabelThatDoesNotExistStillPointsAtCreate() throws Exception {
		String out = error(rename, Map.of("kind", "label", "address", "1000:0210",
			"new_name", "nothing_here"));
		assertTrue(out, out.contains("create kind=label"));
	}
}
