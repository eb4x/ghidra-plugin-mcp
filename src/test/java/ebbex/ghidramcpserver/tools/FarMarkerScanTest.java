package ebbex.ghidramcpserver.tools;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.util.List;

import org.junit.Test;

import ebbex.ghidramcpserver.tools.DefineTypesTool.FarMark;
import ebbex.ghidramcpserver.tools.DefineTypesTool.FarScan;

/**
 * The far-pointer scanner: CParser tokenises {@code __far}/{@code __ptr32} and discards
 * them and does not know {@code far} at all, so the markers are found and removed before the
 * parse and bound to the declarator they modify.
 */
public class FarMarkerScanTest {

	@Test
	public void fieldMarkersAreOwnedByTheirStruct() {
		FarScan scan = DefineTypesTool.scanFarMarkers(
			"struct A { struct B __far *p; char far *s; int n; };");
		assertEquals(List.of(new FarMark("A", "p"), new FarMark("A", "s")), scan.marks());
		assertFalse(scan.source().contains("__far"));
		assertFalse(scan.source().contains("far"));
		assertTrue(scan.source().replaceAll("\\s+", " ").contains("struct B *p"));
	}

	@Test
	public void markerAfterTheStarBindsToTheSameName() {
		FarScan scan = DefineTypesTool.scanFarMarkers("typedef struct B * __far BFar;");
		assertEquals(List.of(new FarMark(null, "BFar")), scan.marks());
	}

	@Test
	public void ptr32IsAFarMarker() {
		FarScan scan = DefineTypesTool.scanFarMarkers("struct A { int __ptr32 *q; };");
		assertEquals(List.of(new FarMark("A", "q")), scan.marks());
	}

	@Test
	public void parametersAreOwnedByTheirFunction() {
		FarScan scan = DefineTypesTool.scanFarMarkers("int f(char __far *buf, int n);");
		assertEquals(List.of(new FarMark("f", "buf")), scan.marks());
	}

	@Test
	public void qualifiersBetweenMarkerAndNameAreSkipped() {
		FarScan scan = DefineTypesTool.scanFarMarkers("struct A { char __far * const name; };");
		assertEquals(List.of(new FarMark("A", "name")), scan.marks());
	}

	@Test
	public void aFieldNamedFarSurvives() {
		FarScan scan = DefineTypesTool.scanFarMarkers("struct A { int far; int near; };");
		assertTrue(scan.marks().isEmpty());
		assertTrue(scan.source().contains("int far;"));
	}

	@Test
	public void commentsAreIgnored() {
		FarScan scan = DefineTypesTool.scanFarMarkers(
			"/* __far * x */ struct A { int a; }; // far *y");
		assertTrue(scan.marks().isEmpty());
	}

	@Test
	public void nestedStructsOwnTheirOwnFields() {
		FarScan scan = DefineTypesTool.scanFarMarkers(
			"struct Outer { struct Inner { char __far *i; } in; int __far *o; };");
		assertEquals(List.of(new FarMark("Inner", "i"), new FarMark("Outer", "o")), scan.marks());
	}
}
