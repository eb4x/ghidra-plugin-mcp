package ebbex.ghidramcpserver.util;

import java.lang.reflect.Field;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import db.DBHandle;
import db.buffers.ManagedBufferFile;
import ghidra.framework.data.DefaultProjectData;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.ProjectData;
import ghidra.framework.store.DatabaseItem;
import ghidra.framework.store.FolderItem;
import ghidra.program.database.DBStringMapAdapter;
import ghidra.program.database.ProgramContentHandler;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.lang.LanguageNotFoundException;
import ghidra.program.model.lang.LanguageVersionException;
import ghidra.program.util.DefaultLanguageService;

/**
 * Whether a program on disk can be opened by this server as it stands, answered <em>without
 * opening it</em>: its database schema and its processor language must both be current.
 *
 * <p>A SLEIGH spec that gains a version, or a Ghidra release that bumps the program schema,
 * leaves every program saved before it unopenable until someone upgrades it, and nothing
 * announces that: the first anyone knows is a tool call failing on a program that worked
 * yesterday. Whole projects can be in that state at once (a 4.7 &rarr; 4.8 x86 bump did exactly
 * this here, and so did 12.2's schema 33), so the listing is where it has to show.
 *
 * <p>The schema version is the same table's {@code "DB Version"}. {@code ProgramDB} refuses an
 * open for update (the only way this server opens programs) when it is below its own
 * {@code DB_VERSION}, and any open when it is above, so that is the whole test here.
 *
 * <p>The language record lives in the program database's {@code Program} table, the
 * {@link DBStringMapAdapter} that {@code ProgramDB} writes at creation and the open path reads
 * back &mdash; {@code "Language ID"} and {@code "Language Version"}. That, and not
 * {@code DomainFile.getMetadata()}, is the source of "Minor language change 4.7 -&gt; 4.8".
 *
 * <p>An earlier version of this class read {@code getMetadata()} instead, which only
 * <em>derives</em> a display string from fields the open path has already loaded. It agreed
 * whenever a program's separate {@code Metadata} table happened to exist and went silent
 * otherwise, which made a whole project (mads: 672 of 672, including a program imported and
 * saved seconds earlier) report "unreadable" while another read clean. The fault was never in
 * the files. Diagnosed by {@code dailydriver} from the DB side after
 * {@code ghidra-plugin-rtlink} proved by control that the discriminator was the project.
 *
 * <p>Every failure here is named rather than swallowed. The path this replaced caught
 * {@code FileNotFoundException} and {@code Field.UnsupportedFieldException} silently and
 * returned an empty map for a non-database item, so three quite different situations arrived as
 * one indistinguishable "no answer" &mdash; which is exactly what made the above take four
 * sessions and two retractions to pin down.
 */
public final class UpgradeStatus {

	/** Table holding the language record: {@code ProgramDB.DATA_MAP_TABLE_NAME}. */
	private static final String PROGRAM_TABLE = "Program";

	/** {@code ProgramDB.PROGRAM_DB_VERSION}; absent or unparsable reads as 1, as the open path does. */
	private static final String DB_VERSION = "DB Version";

	private static final String LANGUAGE_ID = "Language ID";
	private static final String LANGUAGE_VERSION = "Language Version";

	/**
	 * Pre-language-ID form, still all that very old databases carry. The open path maps it
	 * through {@code OldLanguageMappingService}; we only need to know it is there, so that such
	 * a file is reported as "recorded differently", never as "no language recorded".
	 */
	private static final String OLD_LANGUAGE_NAME = "Language Name";

	private static final Pattern VERSION = Pattern.compile("^(\\d+)\\.(\\d+)$");

	/** Marks a verdict of "could not tell", as against a verdict about the program. */
	private static final String UNKNOWN_PREFIX = "language version unreadable";

	private UpgradeStatus() {
	}

	/** The schema counterpart of {@link #UNKNOWN_PREFIX}. */
	private static final String SCHEMA_UNKNOWN_PREFIX = "schema version unreadable";

	/**
	 * The running Ghidra's {@code ProgramDB.DB_VERSION}, or -1 if it cannot be read. It is
	 * package-private there, and read reflectively so the check follows whichever Ghidra is
	 * running rather than the one this was compiled against.
	 */
	private static final int CURRENT_SCHEMA = currentSchema();

	/** True when {@code staleness} reports our own ignorance rather than a verdict. */
	public static boolean isUnreadable(String staleness) {
		return staleness != null &&
			(staleness.startsWith(UNKNOWN_PREFIX) || staleness.startsWith(SCHEMA_UNKNOWN_PREFIX));
	}

	private static int currentSchema() {
		try {
			Field field = ProgramDB.class.getDeclaredField("DB_VERSION");
			field.setAccessible(true);
			return field.getInt(null);
		}
		catch (ReflectiveOperationException | RuntimeException e) {
			return -1;
		}
	}

	/**
	 * The schema verdict on a stored {@code "DB Version"}, or {@code null} when it is current.
	 * Mirrors {@code ProgramDB.initializeProgramInfo} for an open for update: above the running
	 * version is never openable, below it needs the one-way upgrade.
	 */
	static String schema(String stored) {
		if (CURRENT_SCHEMA < 0) {
			return SCHEMA_UNKNOWN_PREFIX + " — this Ghidra's ProgramDB.DB_VERSION could not be read";
		}
		int version = 1;
		if (stored != null) {
			try {
				version = Integer.parseInt(stored.trim());
			}
			catch (NumberFormatException e) {
				// The open path reads an unparsable version as 1 too.
			}
		}
		if (version > CURRENT_SCHEMA) {
			return "saved by a newer Ghidra (program schema v" + version + "; this one reads up " +
				"to v" + CURRENT_SCHEMA + "), so it cannot be opened or upgraded here";
		}
		if (version < CURRENT_SCHEMA) {
			return "needs upgrade — program schema v" + version + ", this Ghidra writes v" +
				CURRENT_SCHEMA;
		}
		return null;
	}

	/** Both verdicts on one row, a certain one first so an unreadable one keeps its prefix. */
	private static String combine(String first, String second) {
		if (first == null || second == null) {
			return first != null ? first : second;
		}
		if (isUnreadable(first) && !isUnreadable(second)) {
			return combine(second, first);
		}
		return first + "; and " + second;
	}

	/**
	 * A short note on why {@code file} cannot be opened as it stands, or {@code null} when its
	 * schema and language are both current. Never throws: a listing must not fail because one
	 * file among hundreds cannot be read.
	 */
	public static String staleness(ProjectData projectData, DomainFile file) {
		if (!ProgramContentHandler.PROGRAM_CONTENT_TYPE.equals(file.getContentType())) {
			return null;
		}
		try {
			return check(projectData, file);
		}
		catch (Exception e) {
			return unknown("reading it raised " + e.getClass().getSimpleName() +
				(e.getMessage() == null ? "" : ": " + e.getMessage()));
		}
	}

	private static String check(ProjectData projectData, DomainFile file) throws Exception {
		if (!(projectData instanceof DefaultProjectData defaultData)) {
			return unknown("this project's data is a " + projectData.getClass().getSimpleName() +
				", which does not expose the file store");
		}
		String fileId = file.getFileID();
		if (fileId == null) {
			return unknown("the file has no ID to look it up by");
		}
		// By ID, not folder+name: the ID survives renames and moves (as DomainFileIndex does it).
		FolderItem item = defaultData.getPrivateFileSystem().getItem(fileId);
		if (item == null) {
			// The private file system holds local items only. A versioned file that is not
			// checked out lives in the versioned store, whose accessor is package-private, so
			// this is a limit of ours and must not read as a fact about the program.
			if (file.isVersioned() && !file.isCheckedOut()) {
				return unknown("it is versioned and not checked out, so its bytes are in the " +
					"versioned store, which this check cannot reach");
			}
			return unknown("the project's private file store has no item with this file's ID");
		}
		if (!(item instanceof DatabaseItem databaseItem)) {
			return unknown("its stored item is a " + item.getClass().getSimpleName() +
				", not a database");
		}
		return fromDatabase(databaseItem);
	}

	private static String fromDatabase(DatabaseItem item) throws Exception {
		ManagedBufferFile bufferFile = item.open();
		DBHandle handle = null;
		try {
			handle = new DBHandle(bufferFile);
			DBStringMapAdapter record = new DBStringMapAdapter(handle, PROGRAM_TABLE, false);
			String schema = schema(record.get(DB_VERSION));
			String id = record.get(LANGUAGE_ID);
			if (id == null) {
				return combine(schema, record.get(OLD_LANGUAGE_NAME) != null
						? unknown("it predates language IDs and records only a language name, " +
							"which only the open path can translate")
						: unknown("its " + PROGRAM_TABLE + " table records no language"));
			}
			return combine(schema, compare(id, record.get(LANGUAGE_VERSION)));
		}
		finally {
			if (handle != null) {
				handle.close();
			}
			bufferFile.dispose();
		}
	}

	private static String compare(String id, String storedVersion) {
		if (storedVersion == null) {
			// The open path defaults a missing version to 1.0. Absent is not "current", and
			// assuming it would manufacture "needs upgrade" against any language past 1 — a
			// false positive, and acting on one means a one-way upgrade of someone's program.
			return unknown("it records language " + id + " with no version, so whether it " +
				"matches the installed one cannot be told from the file");
		}
		Matcher matcher = VERSION.matcher(storedVersion.trim());
		if (!matcher.matches()) {
			return unknown("its language version reads '" + storedVersion + "', which is not a " +
				"major.minor number");
		}
		Language language;
		try {
			language = DefaultLanguageService.getLanguageService().getLanguage(new LanguageID(id));
		}
		catch (LanguageNotFoundException e) {
			return "language " + id + " is not installed in this Ghidra";
		}
		int major = Integer.parseInt(matcher.group(1));
		int minor = Integer.parseInt(matcher.group(2));
		try {
			LanguageVersionException upgrade = LanguageVersionException.check(language, major, minor);
			return upgrade == null ? null : "needs upgrade — " + reason(upgrade);
		}
		catch (LanguageNotFoundException e) {
			return "saved under " + id + " " + major + "." + minor + ", which this Ghidra cannot " +
				"translate to its installed version";
		}
	}

	private static String reason(LanguageVersionException e) {
		if (e.getMessage() != null) {
			return e.getMessage();
		}
		return e.getDetailMessage() != null ? e.getDetailMessage() : "language version changed";
	}

	/**
	 * An admission, naming the specific reason. The standing "this is not clean" caveat belongs
	 * in the caller's footer, once, rather than repeated down hundreds of rows.
	 */
	private static String unknown(String why) {
		return UNKNOWN_PREFIX + " — " + why;
	}
}
