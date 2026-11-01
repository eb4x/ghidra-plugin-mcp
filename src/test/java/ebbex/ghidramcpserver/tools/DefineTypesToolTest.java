package ebbex.ghidramcpserver.tools;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.junit.Test;

import ebbex.ghidramcpserver.RealModeProgramTest;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Enum;
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

	/**
	 * Storing the first struct resolves every type it refers to into the program, so a struct
	 * the same call defines later must still read as new, not as "already identical".
	 */
	@Test
	public void aStructPulledInByAnEarlierOneIsStillNew() throws Exception {
		String out = ok(defineTypes, Map.of("source",
			"struct Alpha { struct Beta *p; };\nstruct Beta { int x; };"));
		assertTrue(out, out.contains("struct Alpha  2 bytes, pack()  new") ||
			out.matches("(?s).*struct Alpha  [^\\n]*  new\\n.*"));
		assertTrue(out, out.matches("(?s).*struct Beta  [^\\n]*  new.*"));
		assertTrue(out, !out.contains("already identical"));
	}

	@Test
	public void enumUnderlyingTypeSetsItsSize() throws Exception {
		String out = ok(defineTypes, Map.of("source",
			"enum Err : char { E_OPEN = 1, E_READ = 2 };\nenum Wide : long { W_A = 0x12345 };"));
		List<DataType> found = new ArrayList<>();
		program.getDataTypeManager().findDataTypes("Err", found);
		assertEquals(1, found.size());
		assertEquals("declared 1 byte", 1, found.get(0).getLength());
		found.clear();
		program.getDataTypeManager().findDataTypes("Wide", found);
		Enum wide = (Enum) found.get(0);
		assertEquals("declared long: 4 bytes in a 16-bit program", 4, wide.getLength());
		assertEquals("the wide value is kept", 0x12345, wide.getValue("W_A"));
		assertTrue(out, out.contains("enum Err  1 byte"));

		// Stock 12.2 drops the misfit and a fixed parser widens the enum; both are refused, naming it.
		String refused = error(defineTypes, Map.of("source", "enum Big : char { A = 1, B = 300 };"));
		assertTrue(refused, refused.contains("enum Big: B do not fit its declared type 'char'"));
		String noClause = error(defineTypes, Map.of("source", "enum Huge { H = 0x12345 };"));
		assertTrue(noClause, noClause.contains("enum Huge: H do not fit int (2 bytes"));
		List<DataType> none = new ArrayList<>();
		program.getDataTypeManager().findDataTypes("Big", none);
		program.getDataTypeManager().findDataTypes("Huge", none);
		assertTrue("a refusal defines nothing", none.isEmpty());
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

	/**
	 * VICEROY's case: sav_unit_kind sorts first and embeds the new sav_unit_land by value, so
	 * storing it replaces the old one in place. sav_unit_land's own verdict must still compare
	 * against the old layout, and the types outside the snippet that embed it and grew are named.
	 */
	@Test
	public void aTypeReplacedByAnEarlierOneStillReadsRedefined() throws Exception {
		ok(defineTypes, Map.of("source", """
			#pragma pack(1)
			typedef unsigned char u8;
			typedef short s16;
			struct sav_unit_land { u8 ai_counter; u8 ai_countdown;
				union { u8 ai_search_slot; s16 created_turn; } k; u8 wants_trade; u8 tools; };
			union sav_unit_payload { u8 hold[6]; struct sav_unit_land land; };
			struct sav_unit { u8 head[16]; union sav_unit_payload u; s16 turn_counter; u8 tail[4]; };
			"""));
		assertEquals(28, struct("sav_unit").getLength());

		String out = ok(defineTypes, Map.of("source", """
			#pragma pack(1)
			struct sav_unit_cargo { u8 item_0 : 4; u8 item_1 : 4; u8 item_2 : 4;
				u8 item_3 : 4; u8 item_4 : 4; u8 item_5 : 4; };
			struct sav_unit_ship { struct sav_unit_cargo cargo; u8 cargo_amount[6]; };
			struct sav_unit_wagon { struct sav_unit_cargo cargo; u8 cargo_amount[2]; u8 unk18[2];
				u8 wants_trade; u8 unk21; };
			struct sav_unit_land { u8 unk13[3]; u8 ai_counter; u8 ai_countdown; u8 ai_search_slot;
				u8 unk19[2]; u8 tools; };
			struct sav_unit_native { u8 unk13[5]; s16 stamp_turn; u8 unk20[2]; };
			union sav_unit_kind { struct sav_unit_ship ship; struct sav_unit_wagon wagon;
				struct sav_unit_land land; struct sav_unit_native native; };
			"""));
		assertTrue(out, out.contains(
			"struct sav_unit_land  9 bytes, pack(1)  REDEFINED in place (was 6 bytes)"));
		assertTrue(out, out.contains("Resized because they contain a redefined type: " +
			"sav_unit 28 → 31 (0x1f) bytes, sav_unit_payload 6 → 9 bytes"));
		assertEquals(31, struct("sav_unit").getLength());
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
