package ebbex.ghidramcpserver.tools.app;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.Map;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

import ebbex.ghidramcpserver.ApplicationLevelTool;
import ebbex.ghidramcpserver.util.Args;
import ebbex.ghidramcpserver.util.Results;
import ebbex.ghidramcpserver.util.Schemas;
import ghidra.framework.Application;
import ghidra.framework.LoggingInitialization;
import ghidra.framework.model.Project;
import io.modelcontextprotocol.spec.McpSchema;

/**
 * Read the running Ghidra instance's {@code application.log}. Because the server lives inside
 * the Ghidra process, it resolves the path the instance is actually writing to (via
 * {@link LoggingInitialization#getApplicationLogFile()}), so there is no ambiguity about which
 * instance's log you are reading — the exact problem that motivated this tool. Analyzer messages
 * ({@code Msg.*} / {@code MessageLog}) surface only here, so this is the post-hoc window into
 * analysis behaviour.
 */
public class ReadLogTool implements ApplicationLevelTool {

	private static final int DEFAULT_TAIL = 200;

	/** A line that begins a new log entry: the "yyyy-MM-dd HH:mm:ss " timestamp prefix. */
	private static final Pattern ENTRY_START =
		Pattern.compile("^\\d{4}-\\d{2}-\\d{2} \\d{2}:\\d{2}:\\d{2} ");

	@Override
	public String name() {
		return "read_log";
	}

	@Override
	public String description() {
		return "Read this running Ghidra instance's application.log (resolved in-process, so it is " +
			"unambiguously the log this instance writes — not another install's). Returns the last " +
			"matching entries, newest last, after the resolved 'Log:' path. Analyzer/import messages " +
			"(e.g. auto-analysis 'Analysis Log Messages') appear here and nowhere else in tool " +
			"output. Multi-line stack traces are kept whole.";
	}

	@Override
	public Map<String, Object> inputSchema() {
		return Map.of(
			"type", "object",
			"properties", Map.of(
				"tail", Schemas.intProp("Return at most the last N matching entries (default " +
					DEFAULT_TAIL + ")"),
				"filter", Schemas.stringProp(
					"Keep only entries containing this (case-insensitive substring by default)"),
				"regex", Schemas.boolProp(
					"Treat 'filter' as a case-insensitive Java regex instead of a substring " +
						"(default false)"),
				"since", Schemas.stringProp("Keep only entries at/after this timestamp, compared " +
					"against the leading 'yyyy-MM-dd HH:mm:ss' (e.g. '2026-07-07' or " +
					"'2026-07-07 10:30:00')")));
	}

	@Override
	public boolean isReadOnly() {
		return true;
	}

	@Override
	public boolean requiresProject() {
		// The log is most valuable exactly when things break before a project opens (import /
		// startup failures), so this tool must not be gated on an open project.
		return false;
	}

	@Override
	public McpSchema.CallToolResult execute(Map<String, Object> args, Project project) {
		File logFile = applicationLogFile();
		if (logFile == null) {
			return Results.error("Could not resolve the application log file (logging may be " +
				"disabled in this instance).");
		}
		if (!logFile.isFile()) {
			return Results.ok("Log: " + logFile.getAbsolutePath() + "\n(the log file does not " +
				"exist yet)");
		}

		int tail = Math.max(1, Args.intArg(args, "tail", DEFAULT_TAIL));
		String filter = Args.stringArg(args, "filter", "");
		boolean regex = Args.boolArg(args, "regex", false);
		String since = Args.stringArg(args, "since", "");

		Pattern pattern = null;
		if (!filter.isEmpty() && regex) {
			try {
				pattern = Pattern.compile(filter, Pattern.CASE_INSENSITIVE);
			}
			catch (PatternSyntaxException e) {
				return Results.error("Invalid regex 'filter': " + e.getMessage());
			}
		}
		String needle = filter.toLowerCase();

		Deque<String> kept = new ArrayDeque<>();
		long[] stats = new long[2]; // {linesScanned, matchingEntries}
		try {
			tailEntries(logFile, tail, since, needle, pattern, kept, stats);
		}
		catch (IOException e) {
			return Results.error("Failed to read " + logFile.getAbsolutePath() + ": " +
				e.getMessage());
		}

		StringBuilder sb = new StringBuilder("Log: ").append(logFile.getAbsolutePath()).append('\n');
		if (kept.isEmpty()) {
			return Results.ok(sb.append("(no matching entries in ").append(stats[0])
					.append(" lines scanned)").toString());
		}
		for (String entry : kept) {
			sb.append(entry).append('\n');
		}
		sb.append(footer(kept.size(), stats[1], stats[0]));
		return Results.ok(sb.toString());
	}

	/**
	 * Stream the log, grouping timestamped lines with their continuation lines into entries,
	 * and retain only the last {@code tail} entries that pass {@code since} and the filter.
	 * Memory stays O(tail): {@code kept} is capped and each entry is built one at a time.
	 */
	private static void tailEntries(File logFile, int tail, String since, String needle,
			Pattern pattern, Deque<String> kept, long[] stats) throws IOException {
		try (BufferedReader reader =
			Files.newBufferedReader(logFile.toPath(), StandardCharsets.UTF_8)) {
			StringBuilder entry = null;
			String line;
			while ((line = reader.readLine()) != null) {
				stats[0]++;
				if (ENTRY_START.matcher(line).find() || entry == null) {
					// Start of a new entry (or leading pre-timestamp lines): flush the previous one.
					accept(entry, since, needle, pattern, kept, tail, stats);
					entry = new StringBuilder(line);
				}
				else {
					// Continuation line (stack trace etc.) — keep it attached to the current entry.
					entry.append('\n').append(line);
				}
			}
			accept(entry, since, needle, pattern, kept, tail, stats);
		}
	}

	/** Apply since + filter to a completed entry; if it passes, append it to the capped deque. */
	private static void accept(StringBuilder entry, String since, String needle, Pattern pattern,
			Deque<String> kept, int tail, long[] stats) {
		if (entry == null) {
			return;
		}
		String text = entry.toString();
		if (!since.isEmpty() && beforeSince(text, since)) {
			return;
		}
		if (pattern != null) {
			if (!pattern.matcher(text).find()) {
				return;
			}
		}
		else if (!needle.isEmpty() && !text.toLowerCase().contains(needle)) {
			return;
		}
		stats[1]++;
		kept.addLast(text);
		while (kept.size() > tail) {
			kept.removeFirst();
		}
	}

	/**
	 * True if the entry's leading "yyyy-MM-dd HH:mm:ss" timestamp sorts before {@code since}.
	 * Compared lexically (the format is zero-padded and sortable). Entries without a leading
	 * timestamp are never dropped by {@code since}.
	 */
	private static boolean beforeSince(String entry, String since) {
		if (!ENTRY_START.matcher(entry).find()) {
			return false;
		}
		int len = Math.min(since.length(), 19); // "yyyy-MM-dd HH:mm:ss"
		return entry.substring(0, Math.min(entry.length(), len)).compareTo(
			since.substring(0, len)) < 0;
	}

	private static String footer(int shown, long matching, long scanned) {
		return "(showing last " + shown + " of " + matching + " matching " +
			(matching == 1 ? "entry" : "entries") + "; " + scanned + " lines scanned)";
	}

	/**
	 * The active application log file, or null if it cannot be resolved. Prefers Ghidra's own
	 * {@link LoggingInitialization#getApplicationLogFile()} (what the Front End "Show Log" uses),
	 * then the {@code logFilename} system property the log4j2 appender reads, then the
	 * conventional file under the user settings directory.
	 */
	public static File applicationLogFile() {
		try {
			File file = LoggingInitialization.getApplicationLogFile();
			if (file != null) {
				return file;
			}
		}
		catch (Throwable ignored) {
			// AssertException when logging was never initialized — fall through to fallbacks.
		}
		String property = System.getProperty("logFilename");
		if (property != null && !property.isBlank()) {
			return new File(property);
		}
		try {
			File settings = Application.getUserSettingsDirectory();
			if (settings != null) {
				return new File(settings, "application.log");
			}
		}
		catch (Throwable ignored) {
			// Application not initialized — give up.
		}
		return null;
	}
}
