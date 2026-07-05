package ebbex.ghidramcpserver.tools.app;

import java.io.File;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import ebbex.ghidramcpserver.AppLevelTool;
import ebbex.ghidramcpserver.util.Results;
import ghidra.feature.fid.db.FidDB;
import ghidra.feature.fid.db.FidFile;
import ghidra.feature.fid.db.FidFileManager;
import ghidra.feature.fid.service.FidPopulateResult;
import ghidra.feature.fid.service.FidService;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.model.Project;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import io.modelcontextprotocol.spec.McpSchema;

/**
 * Build a Function ID database (.fidb) from the user-named functions of one or
 * more project programs, so those names can be propagated to sibling binaries of
 * the same toolchain with fid_apply. All source programs must share a language.
 */
public class FidBuildTool implements AppLevelTool {

	@Override
	public String name() {
		return "fid_build";
	}

	@Override
	public String description() {
		return "Build a Function ID database (.fidb) from the named functions of project " +
			"program(s), for later fid_apply to sibling binaries. Give 'db' (output host path) and " +
			"optionally 'programs' (project paths; defaults to every program in the project). All " +
			"sources must share one language. Only user-named functions become useful signatures.";
	}

	@Override
	public Map<String, Object> inputSchema() {
		return Map.of(
			"type", "object",
			"properties", Map.of(
				"db", Results.stringProp("Output host path for the .fidb (created if absent)"),
				"programs", Map.of("type", "array", "description",
					"Project file paths to ingest (default: all programs)",
					"items", Map.of("type", "string")),
				"library", Results.stringProp("Library family name label (default 'corpus')"),
				"version", Results.stringProp("Library version label (default '1')"),
				"variant", Results.stringProp("Library variant label (default 'default')")),
			"required", List.of("db"));
	}

	@Override
	public boolean isReadOnly() {
		return false;
	}

	@Override
	public McpSchema.CallToolResult execute(Map<String, Object> args, Project project)
			throws Exception {
		String dbPath = Results.stringArg(args, "db", null);
		if (dbPath == null) {
			return Results.error("db is required");
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

		String family = Results.stringArg(args, "library", "corpus");
		String version = Results.stringArg(args, "version", "1");
		String variant = Results.stringArg(args, "variant", "default");

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
			FidPopulateResult result = service.createNewLibraryFromPrograms(fidDb, family, version,
				variant, programs, /*functionFilter*/ null, languageId, /*linkLibraries*/ null,
				/*commonSymbols*/ List.of(), TaskMonitor.DUMMY);
			fidDb.saveDatabase("Saving", TaskMonitor.DUMMY);
			message = "Ingested " + result.getTotalAdded() + " of " + result.getTotalAttempted() +
				" functions from " + programs.size() + " program(s) into " + dbPath +
				" (language " + languageId + ").";
		}
		finally {
			fidDb.close();
		}
		// This FidFile cached its (empty) supported-languages when getFidDB opened the
		// not-yet-populated DB. Discard it so a later fid_apply re-reads the finished DB.
		fidManager.removeUserFile(fidFile);
		return Results.ok(message);
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
