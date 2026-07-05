package ebbex.ghidramcpserver.tools.app;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import ebbex.ghidramcpserver.ApplicationLevelTool;
import ebbex.ghidramcpserver.util.Args;
import ebbex.ghidramcpserver.util.Results;
import ebbex.ghidramcpserver.util.Schemas;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.model.Project;
import ghidra.framework.model.ProjectData;
import io.modelcontextprotocol.spec.McpSchema;

/** List the files (and folders) in the project, with their content types. */
public class ListFilesTool implements ApplicationLevelTool {

	private static final int DEFAULT_LIMIT = 200;

	@Override
	public String name() {
		return "list_files";
	}

	@Override
	public String description() {
		return "List files in the project. Each file's path (usable as the 'program' argument of " +
			"program tools) and content type are shown. Defaults to a recursive listing from the " +
			"root; pass 'folder' to scope it and 'recursive'=false for a single level.";
	}

	@Override
	public Map<String, Object> inputSchema() {
		return Map.of(
			"type", "object",
			"properties", Map.of(
				"folder", Schemas.stringProp("Project folder to list (default '/')"),
				"recursive", Schemas.boolProp("Recurse into subfolders (default true)"),
				"filter", Schemas.stringProp("Case-insensitive substring to match against paths"),
				"offset", Schemas.intProp("Skip this many matches (default 0)"),
				"limit", Schemas.intProp("Maximum files to return (default " + DEFAULT_LIMIT + ")")));
	}

	@Override
	public boolean isReadOnly() {
		return true;
	}

	@Override
	public McpSchema.CallToolResult execute(Map<String, Object> args, Project project) {
		String folderPath = Args.stringArg(args, "folder", "/");
		boolean recursive = Args.boolArg(args, "recursive", true);
		String filter = Args.stringArg(args, "filter", "").toLowerCase();
		int offset = Math.max(0, Args.intArg(args, "offset", 0));
		int limit = Math.max(1, Args.intArg(args, "limit", DEFAULT_LIMIT));

		ProjectData data = project.getProjectData();
		DomainFolder folder = data.getFolder(folderPath);
		if (folder == null) {
			return Results.error("No project folder '" + folderPath + "'");
		}

		List<String> matches = new ArrayList<>();
		collect(folder, recursive, filter, matches);

		if (matches.isEmpty()) {
			return Results.ok("No files" + (filter.isEmpty() ? "" : " matching '" + filter + "'") +
				" under " + folderPath);
		}
		List<String> window = matches.stream().skip(offset).limit(limit).toList();
		return Results.ok(String.join("\n", window) + (window.isEmpty() ? "" : "\n") +
			Results.paginationFooter(window.size(), offset, matches.size()));
	}

	private static void collect(DomainFolder folder, boolean recursive, String filter,
			List<String> out) {
		for (DomainFile file : folder.getFiles()) {
			String path = file.getPathname();
			if (!filter.isEmpty() && !path.toLowerCase().contains(filter)) {
				continue;
			}
			out.add(path + "  [" + file.getContentType() + "]");
		}
		if (recursive) {
			for (DomainFolder sub : folder.getFolders()) {
				collect(sub, true, filter, out);
			}
		}
	}
}
