package ebbex.ghidramcpserver.tools.app;

import java.io.File;
import java.util.Map;

import ebbex.ghidramcpserver.ApplicationLevelTool;
import ebbex.ghidramcpserver.util.BuildInfo;
import ebbex.ghidramcpserver.util.ProjectContext;
import ebbex.ghidramcpserver.util.Results;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.model.Project;
import io.modelcontextprotocol.spec.McpSchema;

/** Snapshot of the active Ghidra project: name, location, and file counts. */
public class GetApplicationInfoTool implements ApplicationLevelTool {

	@Override
	public String name() {
		return "get_application_info";
	}

	@Override
	public String description() {
		return "Get information about the active Ghidra project: its name, on-disk location, and " +
			"the number of folders and files it contains. Also reports the server's build stamp " +
			"(git commit + build time) — check it to confirm which extension build is serving. " +
			"The location is verified, and flagged [UNREACHABLE] if the project directory has " +
			"been moved or deleted — call this first when program tools fail but listings work.";
	}

	@Override
	public Map<String, Object> inputSchema() {
		return Map.of("type", "object", "properties", Map.of());
	}

	@Override
	public boolean isReadOnly() {
		return true;
	}

	@Override
	public McpSchema.CallToolResult execute(Map<String, Object> args, Project project) {
		int[] counts = new int[2]; // {files, folders}
		count(project.getProjectData().getRootFolder(), counts);

		// The counts above come from ProjectData's in-memory cache, so they answer confidently
		// even when the project's storage has been moved out from under Ghidra. Printing an
		// unverified location next to them is what made that state a multi-turn mystery: this is
		// the tool an agent reaches for when confused, so it has to say when the path is a lie.
		String problem = ProjectContext.storageProblem(project.getProjectLocator());
		String message = "Project: " + project.getName() + "\n" +
			"Location: " + project.getProjectLocator().getLocation() +
			(problem == null ? ""
					: "  [UNREACHABLE — " + problem + "; the project directory has been moved, " +
						"renamed, or deleted since Ghidra opened it]") + "\n" +
			"Folders: " + counts[1] + "\n" +
			"Files: " + counts[0] + "\n" +
			"Server build: " + BuildInfo.describe();
		if (problem != null) {
			message += "\nNote: the counts above are served from Ghidra's in-memory cache and " +
				"still look right, but no file contents can be read — every program tool will " +
				"fail. Reopen the project with manage_project op=open (op=list_recent shows what " +
				"Ghidra knows).";
		}
		File logFile = ReadLogTool.applicationLogFile();
		if (logFile != null) {
			message += "\nLog: " + logFile.getAbsolutePath() + "  (read with read_log)";
		}
		return Results.ok(message);
	}

	private static void count(DomainFolder folder, int[] counts) {
		for (DomainFile file : folder.getFiles()) {
			counts[0]++;
		}
		for (DomainFolder sub : folder.getFolders()) {
			counts[1]++;
			count(sub, counts);
		}
	}
}
