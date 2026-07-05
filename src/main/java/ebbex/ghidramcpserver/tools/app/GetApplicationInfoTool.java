package ebbex.ghidramcpserver.tools.app;

import java.util.Map;

import ebbex.ghidramcpserver.AppLevelTool;
import ebbex.ghidramcpserver.util.Results;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.model.Project;
import io.modelcontextprotocol.spec.McpSchema;

/** Snapshot of the active Ghidra project: name, location, and file counts. */
public class GetApplicationInfoTool implements AppLevelTool {

	@Override
	public String name() {
		return "get_application_info";
	}

	@Override
	public String description() {
		return "Get information about the active Ghidra project: its name, on-disk location, and " +
			"the number of folders and files it contains.";
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

		String message = "Project: " + project.getName() + "\n" +
			"Location: " + project.getProjectLocator().getLocation() + "\n" +
			"Folders: " + counts[1] + "\n" +
			"Files: " + counts[0];
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
