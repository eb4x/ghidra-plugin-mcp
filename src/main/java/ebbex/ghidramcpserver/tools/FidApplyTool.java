package ebbex.ghidramcpserver.tools;

import java.io.File;
import java.util.List;
import java.util.Map;

import ebbex.ghidramcpserver.ProgramTool;
import ebbex.ghidramcpserver.util.Args;
import ebbex.ghidramcpserver.util.Results;
import ebbex.ghidramcpserver.util.Schemas;
import ghidra.feature.fid.cmd.ApplyFidEntriesCommand;
import ghidra.feature.fid.db.FidFileManager;
import ghidra.feature.fid.service.FidService;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import io.modelcontextprotocol.spec.McpSchema;

/**
 * Apply a Function ID database (.fidb) to this program, labelling functions whose
 * code-hash matches a named function in the database. Pairs with fid_build: label
 * one binary, then propagate to others of the same language/toolchain.
 */
public class FidApplyTool implements ProgramTool {

	@Override
	public String name() {
		return "fid_apply";
	}

	@Override
	public String description() {
		return "Apply a Function ID database (.fidb host path) to this program: functions whose " +
			"byte/hash signature matches a named function in the database get that name. The " +
			"database's language must match the program's (build one with fid_build from a labelled " +
			"binary of the same toolchain).";
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

	@Override
	public McpSchema.CallToolResult execute(Map<String, Object> args, Program program) {
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

		int txId = program.startTransaction("Apply FID: " + dbFile.getName());
		int applied = 0;
		boolean commit = false;
		try {
			ApplyFidEntriesCommand cmd = new ApplyFidEntriesCommand(program.getMemory(), score,
				multi, /*alwaysApplyFidLabels*/ false, /*createBookmarks*/ false);
			if (cmd.applyTo(program, TaskMonitor.DUMMY)) {
				applied = (int) cmd.getFIDLocations().getNumAddresses();
			}
			commit = true;
		}
		finally {
			program.endTransaction(txId, commit);
		}

		return Results.ok("Applied " + applied + " FID name(s) from " + dbFile.getName() +
			" to " + program.getName());
	}
}
