package ebbex.ghidramcpserver.tools;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.junit.Test;

import ebbex.ghidramcpserver.RealModeProgramTest;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;

/**
 * define_types on a 16-bit program, where a near pointer is 2 bytes and a far one 4: a
 * body-less reference binds to the existing type instead of emptying it, a redefinition
 * replaces in place and says so, and the far markers widen exactly the pointers they name.
 */
public class DefineTypesToolTest extends RealModeProgramTest {

	private final DefineTypesTool defineTypes = new DefineTypesTool();
	private final ManageTypesTool manageTypes = new ManageTypesTool();

	private Structure struct(String name) {
		List<DataType> found = new ArrayList<>();
		program.getDataTypeManager().findDataTypes(name, found);
		assertEquals("one type named " + name, 1, found.size());
		return (Structure) found.get(0);
	}

	@Test
	public void bodylessReferenceBindsToTheExistingStruct() throws Exception {
		ok(defineTypes, Map.of("source", "struct ColorList { short n; char table[1536]; };"));
		assertEquals(1538, struct("ColorList").getLength());

		String out = ok(defineTypes, Map.of("source",
			"struct Holder { struct ColorList *near_p; };\n" +
				"typedef struct ColorList * __far ColorListFar;"));
		assertEquals("the referenced struct keeps its body", 1538, struct("ColorList").getLength());
		assertTrue(out, out.contains("Existing types used as-is: ColorList (1538 (0x602) bytes)"));
		assertTrue(out, out.contains("typedef ColorListFar = ColorList *32  4 bytes  new"));
	}

	@Test
	public void farMarkersWidenOnlyTheNamedPointers() throws Exception {
		ok(defineTypes, Map.of("source", "struct Hdr { int a; };"));
		String out = ok(defineTypes, Map.of("source",
			"#pragma pack(1)\n" +
				"struct Rec { struct Hdr *near_p; struct Hdr __far *far_p; char far *name; int n; };"));
		Structure rec = struct("Rec");
		assertEquals(2, program.getDataTypeManager().getDataOrganization().getPointerSize());
		assertEquals(2, rec.getComponent(0).getLength());
		assertEquals(4, rec.getComponent(1).getLength());
		assertEquals(4, rec.getComponent(2).getLength());
		assertEquals("2 + 4 + 4 + 2, packed", 12, rec.getLength());
		assertTrue(out, out.contains("Far pointers (4 bytes): Rec.far_p, Rec.name"));
		assertTrue(out, out.contains("pack(1)"));

		String layout = ok(manageTypes, Map.of("op", "describe", "name", "Rec"));
		assertTrue(layout, layout.contains("+0x2: Hdr *32 far_p  (4 bytes)"));
		assertTrue(layout, layout.contains("+0x6: char *32 name  (4 bytes)"));
	}

	@Test
	public void redefinitionReplacesInPlaceAndReportsTheOldSize() throws Exception {
		ok(defineTypes, Map.of("source", "struct Rec { int a; int b; char tail[24]; };"));
		Structure before = struct("Rec");
		assertEquals(28, before.getLength());

		String out = ok(defineTypes, Map.of("source", "struct Rec { int a; };"));
		assertTrue(out, out.contains("REDEFINED in place (was 28 (0x1c) bytes)"));
		assertEquals("same DB object, new body", before.getUniversalID(),
			struct("Rec").getUniversalID());
		assertEquals(2, struct("Rec").getLength());
	}

	@Test
	public void forwardDeclarationAloneIsFlaggedEmpty() throws Exception {
		String out = ok(defineTypes, Map.of("source", "struct Opaque;"));
		assertTrue(out, out.contains("EMPTY"));
	}

	@Test
	public void aParseErrorIsReportedNotThrown() throws Exception {
		String out = error(defineTypes, Map.of("source", "struct { int"));
		assertTrue(out, out.contains("could not parse"));
	}
}
