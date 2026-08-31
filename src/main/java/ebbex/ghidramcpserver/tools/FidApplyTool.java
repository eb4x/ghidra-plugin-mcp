package ebbex.ghidramcpserver.tools;

import java.io.File;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

import ebbex.ghidramcpserver.ProgramTool;
import ebbex.ghidramcpserver.util.Args;
import ebbex.ghidramcpserver.util.Results;
import ebbex.ghidramcpserver.util.Schemas;
import ghidra.feature.fid.cmd.ApplyFidEntriesCommand;
import ghidra.feature.fid.db.FidFileManager;
import ghidra.feature.fid.db.FidQueryService;
import ghidra.feature.fid.db.LibraryRecord;
import ghidra.feature.fid.service.FidMatch;
import ghidra.feature.fid.service.FidSearchResult;
import ghidra.feature.fid.service.FidService;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.task.TaskMonitor;
import io.modelcontextprotocol.spec.McpSchema;

/**
 * Apply a Function ID database (.fidb) to this program, labelling functions whose
 * code-hash matches a named function in the database. Pairs with fid_build: label
 * one binary, then propagate to others of the same language/toolchain.
 *
 * <p>The result names every function it touched &mdash; address, previous name, new
 * name(s), best score, source library &mdash; and every function that matched but was
 * left alone, with why. Ghidra's {@link ApplyFidEntriesCommand} keeps all of that
 * private, so the tool runs the same search the command runs (once more, before it) to
 * learn the candidates, and diffs the symbol table around the command to learn what
 * was applied. The extra search costs one more hash pass, which is cheap next to the
 * database queries.
 */
public class FidApplyTool implements ProgramTool {

	/** Declined-candidate lines are capped so a big library sweep stays readable. */
	private static final int MAX_DECLINED = 100;

	@Override
	public String name() {
		return "fid_apply";
	}

	@Override
	public String description() {
		return "Apply a Function ID database (.fidb host path) to this program: functions whose " +
			"byte/hash signature matches a named function in the database get that name. Reports " +
			"one line per renamed function (address, old -> new name, score, library) and lists " +
			"the functions that matched but were not renamed (a trusted name already there, or " +
			"several candidate names) with their candidates. The database's language must match " +
			"the program's (build one with fid_build from a labelled binary of the same toolchain).";
	}

	@Override
	public Map<String, Object> inputSchema() {
		return Map.of(
			"type", "object",
			"properties", Map.of(
				"fidb", Schemas.stringProp("Host path to the .fidb database"),
				"score_threshold", Schemas.intProp(
					"Minimum match score in code units (default: Ghidra's standard threshold)")),
			"required", List.of("fidb"));
	}

	@Override
	public boolean isReadOnly() {
		return false;
	}

	/** What one function looked like before the command ran, plus its candidates. */
	private record Before(String name, boolean trusted, String candidates) {
	}

	@Override
	public McpSchema.CallToolResult execute(Map<String, Object> args, Program program)
			throws Exception {
		String dbPath = Args.stringArg(args, "fidb", null);
		if (dbPath == null) {
			return Results.error("'fidb' (a host path to the .fidb) is required");
		}
		File dbFile = new File(dbPath);
		if (!dbFile.isFile()) {
			return Results.error("Not a file: " + dbPath);
		}

		FidFileManager fidManager = FidFileManager.getInstance();
		// Re-register fresh so its supported-languages cache is read from the current DB
		// (a stale registration can otherwise report the wrong / no language).
		ghidra.feature.fid.db.FidFile existing = fidManager.addUserFidFile(dbFile);
		if (existing == null) {
			return Results.error("Not a valid FID database: " + dbPath);
		}
		fidManager.removeUserFile(existing);
		if (fidManager.addUserFidFile(dbFile) == null) {
			return Results.error("Not a valid FID database: " + dbPath);
		}
		if (!fidManager.canQuery(program.getLanguage())) {
			return Results.error("No FID database matches this program's language (" +
				program.getLanguageID() + "). Build one with fid_build from a binary of the same " +
				"toolchain.");
		}

		FidService service = new FidService();
		float score = args.containsKey("score_threshold")
				? Args.intArg(args, "score_threshold", 0)
				: service.getDefaultScoreThreshold();
		float multi = service.getDefaultMultiNameThreshold();

		// The candidates: the same search the command is about to run. Everything worth
		// reporting is copied out while the query service is open — a FunctionRecord's name
		// is a lazy lookup in the database's strings table, which closing the service tears
		// down (NPE on getName() afterwards).
		Map<Address, Before> before = new TreeMap<>();
		try (FidQueryService query = service.openFidQueryService(program.getLanguage(), false)) {
			List<FidSearchResult> search =
				service.processProgram(program, query, score, TaskMonitor.DUMMY);
			if (search == null) {
				return Results.error("FID search could not run on " + program.getName());
			}
			for (FidSearchResult result : search) {
				if (result.matches.isEmpty() || result.function.isThunk()) {
					continue;
				}
				Address entry = result.function.getEntryPoint();
				before.put(entry, new Before(result.function.getName(),
					hasTrustedSymbol(program, entry), describeMatches(result)));
			}
		}

		int txId = program.startTransaction("Apply FID: " + dbFile.getName());
		AddressSetView affected = null;
		boolean commit = false;
		String status = null;
		try {
			ApplyFidEntriesCommand cmd = new ApplyFidEntriesCommand(program.getMemory(), score,
				multi, /*alwaysApplyFidLabels*/ false, /*createBookmarks*/ false);
			if (cmd.applyTo(program, TaskMonitor.DUMMY)) {
				affected = cmd.getFIDLocations();
			}
			else {
				status = cmd.getStatusMsg();
			}
			commit = true;
		}
		finally {
			program.endTransaction(txId, commit);
		}
		if (affected == null) {
			return Results.error("FID apply did not run on " + program.getName() +
				(status != null && !status.isBlank() ? ": " + status : ""));
		}

		StringBuilder sb = new StringBuilder();
		int applied = (int) affected.getNumAddresses();
		sb.append("Applied ").append(applied).append(" FID name(s) from ")
				.append(dbFile.getName()).append(" to ").append(program.getName())
				.append(" (").append(before.size()).append(" function(s) matched at score >= ")
				.append(trim(score)).append(")");

		if (applied > 0) {
			sb.append("\nApplied:");
			for (Address entry : affected.getAddresses(true)) {
				Function function = program.getFunctionManager().getFunctionAt(entry);
				Before was = before.get(entry);
				sb.append("\n  ").append(entry).append("  ")
						.append(was != null ? was.name() : "?").append(" -> ")
						.append(function != null ? function.getName() : "?");
				List<String> extra = otherLabels(program, entry);
				if (!extra.isEmpty()) {
					sb.append("  [conflict: also ").append(String.join(", ", extra)).append(']');
				}
				if (was != null) {
					sb.append(was.candidates());
				}
			}
		}

		List<String> declined = new ArrayList<>();
		for (Map.Entry<Address, Before> e : before.entrySet()) {
			Address entry = e.getKey();
			if (affected.contains(entry)) {
				continue;
			}
			Before was = e.getValue();
			declined.add(entry + "  " + was.name() +
				(was.trusted()
						? "  kept (user/imported name; FID never overrides one)"
						: "  not applied") +
				was.candidates());
		}
		if (!declined.isEmpty()) {
			sb.append("\nMatched but not renamed (").append(declined.size()).append("):");
			for (int i = 0; i < Math.min(declined.size(), MAX_DECLINED); i++) {
				sb.append("\n  ").append(declined.get(i));
			}
			if (declined.size() > MAX_DECLINED) {
				sb.append("\n  ... and ").append(declined.size() - MAX_DECLINED).append(" more");
			}
			sb.append("\nA function with several candidate names is renamed only when their " +
				"combined score reaches ").append(trim(multi))
					.append("; then every candidate becomes a label and the primary name gets " +
						"the FID_conflict: prefix.");
		}
		return Results.ok(sb.toString());
	}

	/** "  score N  from a (lib)" or "  score N  candidates: a (lib), b (lib)" — best score first. */
	private static String describeMatches(FidSearchResult result) {
		StringBuilder sb = new StringBuilder();
		float best = 0;
		Set<String> candidates = new LinkedHashSet<>();
		List<FidMatch> sorted = new ArrayList<>(result.matches);
		sorted.sort((a, b) -> Float.compare(b.getOverallScore(), a.getOverallScore()));
		for (FidMatch match : sorted) {
			best = Math.max(best, match.getOverallScore());
			candidates.add(match.getFunctionRecord().getName() + " (" +
				library(match.getLibraryRecord()) + ")");
		}
		sb.append("  score ").append(trim(best));
		sb.append("  ").append(candidates.size() == 1 ? "from " : "candidates: ");
		int shown = 0;
		for (String candidate : candidates) {
			if (shown++ == 5) {
				sb.append(", ... ").append(candidates.size() - 5).append(" more");
				break;
			}
			sb.append(shown > 1 ? ", " : "").append(candidate);
		}
		return sb.toString();
	}

	private static String library(LibraryRecord library) {
		if (library == null) {
			return "?";
		}
		return library.getLibraryFamilyName() + " " + library.getLibraryVersion() + " " +
			library.getLibraryVariant();
	}

	private static String trim(float value) {
		return value == (long) value ? Long.toString((long) value) : String.format("%.1f", value);
	}

	/** True when a USER_DEFINED or IMPORTED symbol sits at the entry — the command's own gate. */
	private static boolean hasTrustedSymbol(Program program, Address entry) {
		for (Symbol symbol : program.getSymbolTable().getSymbols(entry)) {
			if (symbol.getSource().isHigherOrEqualPriorityThan(SourceType.IMPORTED)) {
				return true;
			}
		}
		return false;
	}

	/** Non-primary labels at the entry: the runners-up of a multi-match. */
	private static List<String> otherLabels(Program program, Address entry) {
		List<String> names = new ArrayList<>();
		for (Symbol symbol : program.getSymbolTable().getSymbols(entry)) {
			if (symbol.isPrimary()) {
				continue;
			}
			names.add(symbol.getName());
		}
		return names;
	}
}
