package ebbex.ghidramcpserver.tools.app;

import java.io.File;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import ebbex.ghidramcpserver.ApplicationLevelTool;
import ebbex.ghidramcpserver.util.Args;
import ebbex.ghidramcpserver.util.Results;
import ebbex.ghidramcpserver.util.Schemas;
import ghidra.feature.fid.db.FidDB;
import ghidra.feature.fid.db.FidFile;
import ghidra.feature.fid.db.FidFileManager;
import ghidra.feature.fid.hash.FidHasher;
import ghidra.feature.fid.service.FidPopulateResult;
import ghidra.feature.fid.service.FidPopulateResult.Disposition;
import ghidra.feature.fid.service.FidService;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.model.Project;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.task.TaskMonitor;
import io.modelcontextprotocol.spec.McpSchema;

/**
 * Build a Function ID database (.fidb) from the user-named functions of one or
 * more project programs, so those names can be propagated to sibling binaries of
 * the same toolchain with fid_apply. All source programs must share a language.
 */
public class FidBuildTool implements ApplicationLevelTool {

	@Override
	public String name() {
		return "fid_build";
	}

	@Override
	public String description() {
		return "Build a Function ID database (.fidb) from the named functions of project " +
			"program(s), for later fid_apply to sibling binaries. Give 'fidb' (output host path) " +
			"and optionally 'programs' (project paths; defaults to every program in the project). " +
			"All sources must share one language. Only named (non-default) functions become " +
			"signatures; the result breaks down why the rest were skipped, and detail=true adds " +
			"that breakdown per program.";
	}

	@Override
	public Map<String, Object> inputSchema() {
		return Map.of(
			"type", "object",
			"properties", Map.of(
				"fidb", Schemas.stringProp("Output host path for the .fidb (created if absent)"),
				"programs", Map.of("type", "array", "description",
					"Project file paths to ingest (default: all programs)",
					"items", Map.of("type", "string")),
				"library", Schemas.stringProp("Library family name label (default 'corpus')"),
				"version", Schemas.stringProp("Library version label (default '1')"),
				"variant", Schemas.stringProp("Library variant label (default 'default')"),
				"detail", Schemas.boolProp("Also list, per program, how many functions were " +
					"eligible and why the rest were skipped (default false)")),
			"required", List.of("fidb"));
	}

	@Override
	public boolean isReadOnly() {
		return false;
	}

	@Override
	public McpSchema.CallToolResult execute(Map<String, Object> args, Project project)
			throws Exception {
		String dbPath = Args.stringArg(args, "fidb", null);
		if (dbPath == null) {
			return Results.error("'fidb' (an output host path) is required");
		}

		List<DomainFile> programs = new ArrayList<>();
		Object programsArg = args.get("programs");
		if (programsArg instanceof List<?> list && !list.isEmpty()) {
			for (Object o : list) {
				DomainFile df = project.getProjectData().getFile(String.valueOf(o));
				if (df == null) {
					return Results.error("No project file: " + o);
				}
				programs.add(df);
			}
		}
		else {
			collectPrograms(project.getProjectData().getRootFolder(), programs);
		}
		if (programs.isEmpty()) {
			return Results.error("No programs to ingest");
		}

		LanguageID languageId = languageOf(programs.get(0));

		String library = Args.stringArg(args, "library", "corpus");
		String version = Args.stringArg(args, "version", "1");
		String variant = Args.stringArg(args, "variant", "default");
		boolean detail = Args.boolArg(args, "detail", false);

		FidFileManager fidManager = FidFileManager.getInstance();
		File dbFile = new File(dbPath);
		if (!dbFile.exists()) {
			fidManager.createNewFidDatabase(dbFile);
		}
		FidFile fidFile = fidManager.addUserFidFile(dbFile);
		if (fidFile == null) {
			return Results.error("Could not open/create FID database: " + dbPath);
		}

		FidDB fidDb = fidFile.getFidDB(true);
		String message;
		try {
			FidService service = new FidService();
			FidPopulateResult result = service.createNewLibraryFromPrograms(fidDb, library, version,
				variant, programs, /*functionFilter*/ null, languageId, /*linkLibraries*/ null,
				/*commonSymbols*/ List.of(), TaskMonitor.DUMMY);
			fidDb.saveDatabase("Saving", TaskMonitor.DUMMY);
			message = summarize(result, programs.size(), dbPath, languageId, service, programs,
				detail);
		}
		finally {
			fidDb.close();
		}
		// This FidFile cached its (empty) supported-languages when getFidDB opened the
		// not-yet-populated DB. Discard it so a later fid_apply re-reads the finished DB.
		fidManager.removeUserFile(fidFile);
		return Results.ok(message);
	}

	/**
	 * The ingest's own verdict (exact, including the cross-program duplicate check) plus,
	 * on request, the same classification redone per program. Ghidra reports dispositions
	 * only as a total, so the per-program pass re-runs its rules — default name, thunk,
	 * hashable — with the same hasher; it cannot see duplicates, which are global.
	 */
	private static String summarize(FidPopulateResult result, int programCount, String dbPath,
			LanguageID languageId, FidService service, List<DomainFile> programs, boolean detail)
			throws Exception {
		StringBuilder sb = new StringBuilder();
		Map<Disposition, Integer> failures = result.getFailures();
		sb.append("Ingested ").append(result.getTotalAdded()).append(" of ")
				.append(result.getTotalAttempted()).append(" functions from ").append(programCount)
				.append(" program(s) into ").append(dbPath).append(" (language ").append(languageId)
				.append(").");
		sb.append("\nSkipped: ")
				.append(count(failures, Disposition.NO_DEFINED_SYMBOL)).append(" unnamed (default name), ")
				.append(count(failures, Disposition.IS_THUNK)).append(" thunks, ")
				.append(count(failures, Disposition.FAILS_MINIMUM_SHORTHASH_LENGTH))
				.append(" too short to hash (< ").append(FidService.SHORT_HASH_CODE_UNIT_LENGTH)
				.append(" code units, e.g. husks), ")
				.append(count(failures, Disposition.DUPLICATE_INFO))
				.append(" duplicates of an already-ingested function, ")
				.append(count(failures, Disposition.MEMORY_ACCESS_EXCEPTION))
				.append(" with unreadable bytes.");
		if (result.getTotalAdded() == 0) {
			sb.append("\nNothing usable: name the functions first (a signature needs a " +
				"non-default function name, not a plain label — create kind=functions_at_labels " +
				"turns named labels into functions).");
		}
		if (!detail) {
			return sb.toString();
		}
		sb.append("\nPer program (eligible / functions; unnamed, thunks, too-short, unreadable):");
		Object consumer = new Object();
		for (DomainFile df : programs) {
			Program program = (Program) df.getImmutableDomainObject(consumer,
				DomainFile.DEFAULT_VERSION, TaskMonitor.DUMMY);
			try {
				if (!program.getLanguageID().equals(languageId)) {
					sb.append("\n  ").append(df.getPathname()).append(": skipped, language ")
							.append(program.getLanguageID());
					continue;
				}
				FidHasher hasher = service.getHasher(program);
				int total = 0, eligible = 0, unnamed = 0, thunks = 0, tooShort = 0, unreadable = 0;
				for (Function function : program.getFunctionManager().getFunctions(true)) {
					if (function.isExternal()) {
						continue;
					}
					total++;
					if (function.getSymbol().getSource() == SourceType.DEFAULT) {
						unnamed++;
					}
					else if (function.isThunk()) {
						thunks++;
					}
					else {
						try {
							if (hasher.hash(function) == null) {
								tooShort++;
							}
							else {
								eligible++;
							}
						}
						catch (Exception e) {
							unreadable++;
						}
					}
				}
				sb.append("\n  ").append(df.getPathname()).append(": ").append(eligible)
						.append(" / ").append(total).append("; ").append(unnamed).append(", ")
						.append(thunks).append(", ").append(tooShort).append(", ")
						.append(unreadable);
			}
			finally {
				program.release(consumer);
			}
		}
		return sb.toString();
	}

	private static int count(Map<Disposition, Integer> failures, Disposition disposition) {
		Integer n = failures.get(disposition);
		return n == null ? 0 : n;
	}

	private static void collectPrograms(DomainFolder folder, List<DomainFile> out) {
		for (DomainFile df : folder.getFiles()) {
			if (Program.class.isAssignableFrom(df.getDomainObjectClass())) {
				out.add(df);
			}
		}
		for (DomainFolder sub : folder.getFolders()) {
			collectPrograms(sub, out);
		}
	}

	private static LanguageID languageOf(DomainFile df) throws Exception {
		Object consumer = new Object();
		Program program =
			(Program) df.getImmutableDomainObject(consumer, DomainFile.DEFAULT_VERSION,
				TaskMonitor.DUMMY);
		try {
			return program.getLanguageID();
		}
		finally {
			program.release(consumer);
		}
	}
}
