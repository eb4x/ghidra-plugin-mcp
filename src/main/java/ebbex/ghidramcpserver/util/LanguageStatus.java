package ebbex.ghidramcpserver.util;

import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import ghidra.framework.model.DomainFile;
import ghidra.program.database.ProgramContentHandler;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.lang.LanguageNotFoundException;
import ghidra.program.model.lang.LanguageVersionException;
import ghidra.program.util.DefaultLanguageService;

/**
 * Whether a program on disk still matches the processor language installed today, answered
 * <em>without opening it</em>.
 *
 * <p>A SLEIGH spec that gains a version leaves every program saved under the old one unopenable
 * until someone upgrades it, and nothing announces that: the first anyone knows is a tool call
 * failing on a program that worked yesterday. Whole projects can be in that state at once (a
 * 4.7 &rarr; 4.8 x86 bump did exactly this here), so the listing is where it has to show.
 *
 * <p>The check is cheap because {@link DomainFile#getMetadata()} reads the file's stored
 * metadata table straight out of its database ({@code GhidraFileData.getMetadata} opens the
 * item as a {@code GenericDomainObjectDB}) rather than constructing a {@code Program}. No
 * language is resolved, so the read works on a file that has never been opened and on one too
 * stale to open at all. The stored {@code "Language ID"} carries the version with it &mdash;
 * {@code "x86:LE:16:Real Mode (4.7)"} &mdash; which is what makes the comparison possible.
 *
 * <p>The verdict itself is Ghidra's, not ours: {@link LanguageVersionException#check} is the
 * same call the open path makes, so this reports what opening <em>would</em> do rather than a
 * second opinion that could drift from it.
 */
public final class LanguageStatus {

	/** The stored form: language id, then its major.minor version in parentheses. */
	private static final Pattern STORED_LANGUAGE =
		Pattern.compile("^(\\S+)\\s+\\((\\d+)\\.(-?\\d+)\\)$");

	/**
	 * Returned when the stored language cannot be read at all. Deliberately not silence:
	 * {@code GhidraFileData.getMetadata} hands back an empty map for a non-database item, for a
	 * file that has been deleted, <em>and</em> for one written by a newer Ghidra than this one
	 * (it catches {@code Field.UnsupportedFieldException} and returns the same empty map). An
	 * empty map therefore means "no answer", never "clean" — and treating it as clean would let
	 * the one file nobody should trust look exactly like a healthy one. Raised by
	 * {@code ghidra-plugin-rtlink}, whose own test case could not have caught it.
	 */
	private static final String UNREADABLE =
		"language version unreadable — no metadata in the file. It may have been written by a " +
			"newer Ghidra than this one, in which case nothing here can open it; this is not a " +
			"clean result";

	private LanguageStatus() {
	}

	/** True when {@code staleness} could not judge the file, rather than judging it stale. */
	public static boolean isUnreadable(String staleness) {
		return UNREADABLE.equals(staleness);
	}

	/**
	 * A short note on why {@code file} cannot be opened as it stands, or {@code null} when it is
	 * fine, is not a program, or cannot be judged. Never throws: a listing must not fail because
	 * one file among hundreds has unreadable metadata.
	 */
	public static String staleness(DomainFile file) {
		if (!ProgramContentHandler.PROGRAM_CONTENT_TYPE.equals(file.getContentType())) {
			return null;
		}
		try {
			return check(file);
		}
		catch (Exception e) {
			// Includes the deliberately-unhandled case: metadata that cannot be read at all.
			return null;
		}
	}

	private static String check(DomainFile file) {
		Map<String, String> metadata = file.getMetadata();
		String stored = metadata == null ? null : metadata.get("Language ID");
		if (stored == null) {
			return UNREADABLE;
		}
		Matcher matcher = STORED_LANGUAGE.matcher(stored.trim());
		if (!matcher.matches()) {
			return UNREADABLE;
		}
		LanguageID id = new LanguageID(matcher.group(1));
		int major = Integer.parseInt(matcher.group(2));
		int minor = Integer.parseInt(matcher.group(3));

		Language language;
		try {
			language = DefaultLanguageService.getLanguageService().getLanguage(id);
		}
		catch (LanguageNotFoundException e) {
			return "language " + id + " is not installed in this Ghidra";
		}
		try {
			LanguageVersionException upgrade = LanguageVersionException.check(language, major, minor);
			return upgrade == null ? null : "needs upgrade — " + reason(upgrade);
		}
		catch (LanguageNotFoundException e) {
			// check() throws this for a version mismatch it cannot translate, including a file
			// saved under a NEWER language than the one installed.
			return "saved under " + id + " " + major + "." + minor +
				", which this Ghidra cannot translate to its installed version";
		}
	}

	private static String reason(LanguageVersionException e) {
		if (e.getMessage() != null) {
			return e.getMessage();
		}
		return e.getDetailMessage() != null ? e.getDetailMessage() : "language version changed";
	}
}
