package ebbex.ghidramcpserver.tools.app;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import ebbex.ghidramcpserver.ApplicationLevelTool;
import ebbex.ghidramcpserver.util.Args;
import ebbex.ghidramcpserver.util.LanguageStatus;
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
			"root; pass 'folder' to scope it and 'recursive'=false for a single level. A program " +
			"whose processor language has moved on since it was saved is marked '**': it cannot " +
			"be opened by any tool until it is upgraded, which is checked here so it is found by " +
			"listing rather than by a call failing.";
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

		List<DomainFile> matches = new ArrayList<>();
		collect(folder, recursive, filter, matches);

		if (matches.isEmpty()) {
			return Results.ok("No files" + (filter.isEmpty() ? "" : " matching '" + filter + "'") +
				" under " + folderPath);
		}
		// Staleness is read from each file's database, so it is checked for the page being
		// returned and not for every match: a listing of thousands must not pay for rows the
		// caller never sees.
		List<DomainFile> window = matches.stream().skip(offset).limit(limit).toList();
		StringBuilder sb = new StringBuilder();
		int stale = 0;
		int unreadable = 0;
		for (DomainFile file : window) {
			sb.append(file.getPathname()).append("  [").append(file.getContentType()).append(']');
			String staleness = LanguageStatus.staleness(data, file);
			if (LanguageStatus.isUnreadable(staleness)) {
				unreadable++;
				sb.append("  ?? ").append(staleness);
			}
			else if (staleness != null) {
				stale++;
				sb.append("  ** ").append(staleness);
			}
			sb.append('\n');
		}
		if (stale > 0) {
			sb.append("\n** ").append(stale).append(" of these cannot be opened as they stand. ")
					.append("The processor language moved under them; upgrading rewrites the ")
					.append("program one way and is the owner's call, so no tool here does it. ")
					.append("Open one in the Ghidra window and accept the upgrade prompt, or ")
					.append("re-import.\n");
		}
		if (unreadable > 0) {
			sb.append("\n?? ").append(unreadable).append(" could not be judged either way, each ")
					.append("row saying why. An unreadable language version is not a clean one: ")
					.append("those programs may or may not open, and the only way to find out is ")
					.append("to try one.\n");
		}
		sb.append(Results.paginationFooter(window.size(), offset, matches.size()));
		return Results.ok(sb.toString());
	}

	private static void collect(DomainFolder folder, boolean recursive, String filter,
			List<DomainFile> out) {
		for (DomainFile file : folder.getFiles()) {
			if (!filter.isEmpty() && !file.getPathname().toLowerCase().contains(filter)) {
				continue;
			}
			out.add(file);
		}
		if (recursive) {
			for (DomainFolder sub : folder.getFolders()) {
				collect(sub, true, filter, out);
			}
		}
	}
}
