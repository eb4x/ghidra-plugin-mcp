package ebbex.ghidramcpserver.tools.app;

import java.util.List;
import java.util.Map;

import ebbex.ghidramcpserver.AppLevelTool;
import ebbex.ghidramcpserver.util.ProjectContext;
import ebbex.ghidramcpserver.util.Results;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.model.Project;
import ghidra.framework.model.ProjectData;
import io.modelcontextprotocol.spec.McpSchema;

/** Delete, rename, or move a file within the project. */
public class ManageFilesTool implements AppLevelTool {

	private static final List<String> OPS = List.of("delete", "rename", "move");

	private final ProjectContext context;

	public ManageFilesTool(ProjectContext context) {
		this.context = context;
	}

	@Override
	public String name() {
		return "manage_files";
	}

	@Override
	public String description() {
		return "Delete, rename, or move a project file. op=delete removes 'path'; op=rename gives " +
			"it 'new_name' (leaf name); op=move puts it in 'dest_folder' (created if missing). " +
			"A file open in a CodeBrowser can't be deleted — close it there first.";
	}

	@Override
	public Map<String, Object> inputSchema() {
		return Map.of(
			"type", "object",
			"properties", Map.of(
				"op", Results.enumProp("What to do", OPS),
				"path", Results.stringProp("Project file path, e.g. /malware.exe"),
				"new_name", Results.stringProp("New leaf name (for op=rename)"),
				"dest_folder", Results.stringProp("Destination folder path (for op=move)")),
			"required", List.of("op", "path"));
	}

	@Override
	public boolean isReadOnly() {
		return false;
	}

	@Override
	public McpSchema.CallToolResult execute(Map<String, Object> args, Project project)
			throws Exception {
		String op = Results.stringArg(args, "op", null);
		if (op == null || !OPS.contains(op)) {
			return Results.error("op must be one of " + OPS);
		}
		String path = Results.stringArg(args, "path", null);
		if (path == null) {
			return Results.error("path is required");
		}
		ProjectData data = project.getProjectData();
		DomainFile file = data.getFile(path);
		if (file == null) {
			return Results.error("No project file: " + path);
		}

		// Drop our own cached handle so the operation isn't blocked by us.
		context.release(path);

		return switch (op) {
			case "delete" -> delete(file, path);
			case "rename" -> rename(file, Results.stringArg(args, "new_name", null));
			case "move" -> move(data, file, Results.stringArg(args, "dest_folder", null));
			default -> Results.error("unhandled op " + op);
		};
	}

	private static McpSchema.CallToolResult delete(DomainFile file, String path) throws Exception {
		if (file.isBusy() || file.isOpen()) {
			return Results.error("'" + path + "' is open elsewhere (e.g. a CodeBrowser); " +
				"close it first.");
		}
		file.delete();
		return Results.ok("Deleted " + path);
	}

	private static McpSchema.CallToolResult rename(DomainFile file, String newName)
			throws Exception {
		if (newName == null || newName.isBlank()) {
			return Results.error("new_name is required for op=rename");
		}
		DomainFile renamed = file.setName(newName);
		return Results.ok("Renamed to " + renamed.getPathname());
	}

	private McpSchema.CallToolResult move(ProjectData data, DomainFile file, String destFolder)
			throws Exception {
		if (destFolder == null || destFolder.isBlank()) {
			return Results.error("dest_folder is required for op=move");
		}
		DomainFolder folder = getOrCreateFolder(data, destFolder);
		DomainFile moved = file.moveTo(folder);
		return Results.ok("Moved to " + moved.getPathname());
	}

	private static DomainFolder getOrCreateFolder(ProjectData data, String path) throws Exception {
		DomainFolder existing = data.getFolder(path);
		if (existing != null) {
			return existing;
		}
		DomainFolder current = data.getRootFolder();
		for (String part : path.split("/")) {
			if (part.isEmpty()) {
				continue;
			}
			DomainFolder next = current.getFolder(part);
			current = next != null ? next : current.createFolder(part);
		}
		return current;
	}
}
