package ebbex.ghidramcpserver.tools;

import java.util.Map;

import ebbex.ghidramcpserver.ProgramTool;
import ebbex.ghidramcpserver.util.ProjectContext;
import ebbex.ghidramcpserver.util.Results;
import ghidra.program.model.listing.Program;
import io.modelcontextprotocol.spec.McpSchema;

/**
 * Persist a program's edits now, waiting out a busy program up to a bound. Edits auto-save after
 * each tool call, but a busy program (background analysis, or another writer holding the lock) can
 * defer that save; this flushes those deferred edits — e.g. before restarting Ghidra.
 */
public class SaveTool implements ProgramTool {

	private static final long SAVE_TIMEOUT_MS = 20000;

	@Override
	public String name() {
		return "save";
	}

	@Override
	public String description() {
		return "Persist the program's edits to the project now. Edits normally auto-save after each " +
			"tool call, but a busy program (background analysis, or another writer) can defer that " +
			"save — run this to flush deferred edits, e.g. before restarting Ghidra. Waits up to " +
			(SAVE_TIMEOUT_MS / 1000) + "s for the program to be free.";
	}

	@Override
	public Map<String, Object> inputSchema() {
		return Map.of("type", "object", "properties", Map.of());
	}

	@Override
	public boolean isReadOnly() {
		return false;
	}

	@Override
	public boolean managesSave() {
		return true;
	}

	@Override
	public McpSchema.CallToolResult execute(Map<String, Object> args, Program program)
			throws Exception {
		if (!program.isChanged()) {
			return Results.ok("No unsaved changes in " + program.getName());
		}
		boolean saved = ProjectContext.saveSettled(program, SAVE_TIMEOUT_MS);
		return saved
				? Results.ok("Saved " + program.getName())
				: Results.ok("Still busy (analysis running or another writer holds the lock) — " +
					program.getName() + "'s edits remain unsaved in memory; try again shortly.");
	}
}
