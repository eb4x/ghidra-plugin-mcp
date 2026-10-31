package ebbex.ghidramcpserver.util;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

import generic.test.AbstractGenericTest;
import ghidra.program.database.ProgramDB;

/**
 * The schema verdict follows ProgramDB's own rule for an open for update: the running version
 * is current, anything below needs the upgrade, anything above is never openable, and an absent
 * or unparsable version reads as 1, as the open path reads it.
 */
public class UpgradeStatusTest extends AbstractGenericTest {

	/** {@code ProgramDB.LIBRARY_ORDINAL_ASSIGNMENT_ADDED_VERSION}: 33, 12.2's schema. */
	private static final int CURRENT = ProgramDB.LIBRARY_ORDINAL_ASSIGNMENT_ADDED_VERSION;

	@Test
	public void currentSchemaIsClean() {
		assertNull(UpgradeStatus.schema(Integer.toString(CURRENT)));
	}

	@Test
	public void olderSchemaNeedsTheUpgrade() {
		String verdict = UpgradeStatus.schema(Integer.toString(CURRENT - 1));
		assertEquals("needs upgrade — program schema v" + (CURRENT - 1) +
			", this Ghidra writes v" + CURRENT, verdict);
		assertFalse(UpgradeStatus.isUnreadable(verdict));
	}

	@Test
	public void newerSchemaCannotBeOpened() {
		String verdict = UpgradeStatus.schema(Integer.toString(CURRENT + 1));
		assertTrue(verdict, verdict.startsWith("saved by a newer Ghidra"));
		assertFalse(UpgradeStatus.isUnreadable(verdict));
	}

	@Test
	public void absentOrGarbledReadsAsOne() {
		assertTrue(UpgradeStatus.schema(null).contains("program schema v1,"));
		assertTrue(UpgradeStatus.schema("x").contains("program schema v1,"));
	}
}
