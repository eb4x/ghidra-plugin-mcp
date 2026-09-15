package ebbex.ghidramcpserver.tools.app;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import ebbex.ghidramcpserver.ApplicationLevelTool;
import ebbex.ghidramcpserver.util.Args;
import ebbex.ghidramcpserver.util.Edt;
import ebbex.ghidramcpserver.util.ProjectContext;
import ebbex.ghidramcpserver.util.Results;
import ebbex.ghidramcpserver.util.Schemas;
import ghidra.app.services.ProgramManager;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.model.Project;
import ghidra.framework.model.ProjectData;
import ghidra.framework.model.ToolManager;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import io.modelcontextprotocol.spec.McpSchema;

/** Delete, rename, or move a file or folder within the project. */
public class ManageFilesTool implements ApplicationLevelTool {

	private static final List<String> OPS = List.of("delete", "rename", "move", "copy");
	private static final List<String> ON_DIRTY = List.of("refuse", "discard");

	/** Closing a program in a tool repaints that tool's windows; bounded like manage_project's. */
	private static final long CLOSE_TIMEOUT_MS = 30_000;

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
		return "Delete, rename, move, or copy a project file or folder. op=delete removes 'path' — " +
			"a folder must be empty unless 'recursive' is true; op=rename gives it 'new_name' " +
			"(leaf name); op=move puts it in 'dest_folder' (created if missing); op=copy duplicates " +
			"it into 'dest_folder' (optionally under 'new_name'). op=copy is how you take a BACKUP " +
			"before a risky bulk edit — Ghidra discards its undo history on every save, and this " +
			"server auto-saves after each tool call, so a snapshot is the only way back. To restore " +
			"one: delete the damaged file, then copy the backup to its folder and rename it. " +
			"op=delete first closes the file in any running tool showing it (e.g. a CodeBrowser " +
			"tab); if it has unsaved changes there, the delete refuses unless on_dirty=discard " +
			"(there is no 'save' — deleting destroys the file either way). rename/move/copy work " +
			"on open files as-is.";
	}

	@Override
	public Map<String, Object> inputSchema() {
		return Map.of(
			"type", "object",
			"properties", Map.of(
				"op", Schemas.enumProp("What to do", OPS),
				"path", Schemas.stringProp("Project file or folder path, e.g. /malware.exe"),
				"new_name", Schemas.stringProp("New leaf name (for op=rename, or optionally op=copy)"),
				"dest_folder", Schemas.stringProp("Destination folder path (for op=move|copy)"),
				"recursive", Schemas.boolProp("For op=delete on a folder: also delete everything " +
					"inside it (default false, which fails on a non-empty folder)"),
				"on_dirty", Schemas.enumProp("For op=delete on a file open in a tool with unsaved " +
					"changes: refuse (default) or discard (close it losing the changes, then " +
					"delete). A clean open file is closed and deleted without this.", ON_DIRTY)),
			"required", List.of("op", "path"));
	}

	@Override
	public boolean isReadOnly() {
		return false;
	}

	@Override
	public McpSchema.CallToolResult execute(Map<String, Object> args, Project project)
			throws Exception {
		String op = Args.stringArg(args, "op", null);
		if (op == null || !OPS.contains(op)) {
			return Results.error("op must be one of " + OPS);
		}
		String path = Args.stringArg(args, "path", null);
		if (path == null) {
			return Results.error("path is required");
		}
		ProjectData data = project.getProjectData();

		DomainFile file = findFile(data, path);
		if (file != null) {
			// A busy file has a background task (e.g. analysis) mid-run: releasing our cached
			// handle now could drop the last consumer and close the program under that task,
			// so refuse before touching anything.
			if (file.isBusy()) {
				return Results.error("'" + path + "' is busy — a background task (e.g. analysis) " +
					"is still running on it; wait for it to finish and retry.");
			}
			String onDirty = Args.stringArg(args, "on_dirty", "refuse");
			if (!ON_DIRTY.contains(onDirty)) {
				return Results.error("on_dirty must be one of " + ON_DIRTY);
			}
			// Drop our own cached handle so the operation isn't blocked by us.
			context.release(path);
			return switch (op) {
				case "delete" -> deleteFile(project, file, path, onDirty);
				case "rename" -> rename(file, Args.stringArg(args, "new_name", null));
				case "move" -> move(data, file, Args.stringArg(args, "dest_folder", null));
				case "copy" -> copy(data, file, Args.stringArg(args, "dest_folder", null),
					Args.stringArg(args, "new_name", null));
				default -> Results.error("unhandled op " + op);
			};
		}

		DomainFolder folder = data.getFolder(path);
		if (folder == null) {
			return Results.error("No project file or folder: " + path);
		}
		return switch (op) {
			case "delete" -> deleteFolder(folder, Args.boolArg(args, "recursive", false));
			case "rename" -> renameFolder(folder, Args.stringArg(args, "new_name", null));
			case "move" -> moveFolder(data, folder, Args.stringArg(args, "dest_folder", null));
			default -> Results.error("unhandled op " + op);
		};
	}

	/**
	 * {@code ProjectData.getFile} throws rather than returning null on a folder-shaped path
	 * (bare "/", or any trailing slash), so a folder path has to survive the file lookup to
	 * reach the folder lookup.
	 */
	private static DomainFile findFile(ProjectData data, String path) {
		try {
			return data.getFile(path);
		}
		catch (IllegalArgumentException e) {
			return null;
		}
	}

	private static McpSchema.CallToolResult deleteFile(Project project, DomainFile file,
			String path, String onDirty) throws Exception {
		String closedNote = "";
		if (file.isOpen()) {
			List<OpenIn> holders = openInTools(project, file);
			if (!holders.isEmpty()) {
				String toolNames = holders.stream()
						.map(h -> h.tool().getName())
						.distinct()
						.collect(Collectors.joining(", "));
				if (file.isChanged() && !"discard".equals(onDirty)) {
					return Results.error("'" + path + "' is open in " + toolNames + " with UNSAVED " +
						"changes. Deleting destroys them either way, so this needs an explicit " +
						"on_dirty=discard (there is no 'save' option — the file is being deleted).");
				}
				closeInTools(holders);
				closedNote = " (closed it in " + toolNames + " first)";
			}
		}
		// A consumer this server cannot reach — a dialog, a background service. The GUI is the
		// only place left to close it, so say so instead of letting delete() throw.
		if (file.isOpen()) {
			return Results.error("'" + path + "' is still held open by: " + describeConsumers(file) +
				" — a consumer this server cannot close; close it in the Ghidra GUI first.");
		}
		file.delete();
		return Results.ok("Deleted " + path + closedNote);
	}

	/** A program open in a running tool, with the service that can close it there. */
	private record OpenIn(PluginTool tool, ProgramManager manager, Program program) {
	}

	/**
	 * Every running tool showing {@code file} — the CodeBrowser tab that used to make delete
	 * refuse with "close it there first", which no MCP call could do. Headless has no tool
	 * manager, so that (and a GUI with no running tools) yields an empty list.
	 */
	private static List<OpenIn> openInTools(Project project, DomainFile file) {
		ToolManager toolManager = project.getToolManager();
		if (toolManager == null) {
			return List.of();
		}
		List<OpenIn> holders = new ArrayList<>();
		for (PluginTool tool : toolManager.getRunningTools()) {
			ProgramManager manager = tool.getService(ProgramManager.class);
			if (manager == null) {
				continue;
			}
			for (Program open : manager.getAllOpenPrograms()) {
				if (file.equals(open.getDomainFile())) {
					holders.add(new OpenIn(tool, manager, open));
				}
			}
		}
		return holders;
	}

	/**
	 * Close the program in each holding tool, dirty or not — the caller has already applied the
	 * on_dirty policy. {@code ignoreChanges=true} is what suppresses the save dialog this server
	 * could never answer. One EDT hop for all of them, bounded like manage_project's close.
	 */
	private static void closeInTools(List<OpenIn> holders) throws Exception {
		Edt.runNow(() -> {
			for (OpenIn holder : holders) {
				holder.manager().closeProgram(holder.program(), true);
			}
			return null;
		}, CLOSE_TIMEOUT_MS);
	}

	/** Names of whoever holds the file open, so 'held open' errors say who to close. */
	private static String describeConsumers(DomainFile file) {
		List<?> consumers = file.getConsumers();
		if (consumers.isEmpty()) {
			return "an unknown consumer";
		}
		return consumers.stream()
				.map(c -> c instanceof String s ? s : c.getClass().getSimpleName())
				.distinct()
				.collect(Collectors.joining(", "));
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

	/**
	 * Duplicate a file, e.g. to snapshot a program before a risky bulk edit. The copy is made
	 * from the file's <em>saved</em> state, which is what a backup must capture — take it before
	 * the write, not after. {@code copyTo} auto-uniquifies the leaf name in the destination, so
	 * an explicit {@code new_name} is applied afterwards.
	 */
	private static McpSchema.CallToolResult copy(ProjectData data, DomainFile file,
			String destFolder, String newName) throws Exception {
		if (destFolder == null || destFolder.isBlank()) {
			return Results.error("dest_folder is required for op=copy");
		}
		DomainFolder folder = getOrCreateFolder(data, destFolder);
		DomainFile copied = file.copyTo(folder, TaskMonitor.DUMMY);
		if (newName != null && !newName.isBlank()) {
			copied = copied.setName(newName);
		}
		return Results.ok("Copied " + file.getPathname() + " -> " + copied.getPathname());
	}

	/**
	 * Delete a folder. Ghidra's {@code DomainFolder.delete()} only removes an empty folder, so
	 * {@code recursive} does the depth-first walk itself, the way Ghidra's own project-tree
	 * Delete action does. Unlike that action we cannot prompt, so anything it would ask about
	 * (read-only, versioned) is refused up front instead.
	 */
	private McpSchema.CallToolResult deleteFolder(DomainFolder folder, boolean recursive)
			throws Exception {
		if (folder.getParent() == null) {
			return Results.error("Refusing to delete the project root folder");
		}
		String path = folder.getPathname();
		if (!recursive) {
			if (!folder.isEmpty()) {
				return Results.error(path + " is not empty (" + describeContents(folder) +
					"); pass recursive=true to delete it and everything inside it.");
			}
			folder.delete();
			return Results.ok("Deleted folder " + path);
		}

		// Busy files first (see execute()): releasing our handles could close a program
		// under a background task, so nothing is touched while one is running.
		McpSchema.CallToolResult busy = refuseIfBusyDescendants(folder);
		if (busy != null) {
			return busy;
		}
		// Drop our own cached handles first, as the single-file path does: otherwise the
		// pre-flight below sees programs our decompiler pool holds open and refuses.
		releaseDescendants(folder);

		// Pre-flight, so a refusal deep in the tree can't leave a half-deleted folder behind.
		List<String> blocked = new ArrayList<>();
		checkDeletable(folder, blocked);
		if (!blocked.isEmpty()) {
			return Results.error("Refusing to delete " + path + "; these files are not deletable:" +
				"\n  " + String.join("\n  ", blocked));
		}

		int[] counts = new int[2];
		deleteRecursively(folder, counts);
		return Results.ok("Deleted folder " + path + " (" + counts[0] + " file(s), " + counts[1] +
			" subfolder(s))");
	}

	private static void checkDeletable(DomainFolder folder, List<String> blocked) {
		for (DomainFolder sub : folder.getFolders()) {
			checkDeletable(sub, blocked);
		}
		for (DomainFile file : folder.getFiles()) {
			String why = null;
			if (file.isBusy()) {
				why = "busy (a background task is still running on it)";
			}
			else if (file.isOpen()) {
				why = "held open by: " + describeConsumers(file);
			}
			else if (file.isVersioned()) {
				why = "versioned; delete it from the GUI project tree";
			}
			else if (file.isReadOnly()) {
				why = "read-only";
			}
			if (why != null) {
				blocked.add(file.getPathname() + " — " + why);
			}
		}
	}

	/** Handles on everything under {@code folder} were dropped before the pre-flight check. */
	private static void deleteRecursively(DomainFolder folder, int[] counts) throws Exception {
		for (DomainFolder sub : folder.getFolders()) {
			deleteRecursively(sub, counts);
			counts[1]++;
		}
		for (DomainFile file : folder.getFiles()) {
			file.delete();
			counts[0]++;
		}
		folder.delete();
	}

	private McpSchema.CallToolResult renameFolder(DomainFolder folder, String newName)
			throws Exception {
		if (newName == null || newName.isBlank()) {
			return Results.error("new_name is required for op=rename");
		}
		McpSchema.CallToolResult busy = refuseIfBusyDescendants(folder);
		if (busy != null) {
			return busy;
		}
		releaseDescendants(folder);
		DomainFolder renamed = folder.setName(newName);
		return Results.ok("Renamed to " + renamed.getPathname());
	}

	private McpSchema.CallToolResult moveFolder(ProjectData data, DomainFolder folder,
			String destFolder) throws Exception {
		if (destFolder == null || destFolder.isBlank()) {
			return Results.error("dest_folder is required for op=move");
		}
		String source = folder.getPathname();
		String dest = destFolder.endsWith("/") && destFolder.length() > 1
				? destFolder.substring(0, destFolder.length() - 1)
				: destFolder;
		// Check before getOrCreateFolder, which would otherwise create the descendant first.
		if (dest.equals(source) || dest.startsWith(source + "/")) {
			return Results.error("Can't move " + source + " into itself or one of its descendants");
		}
		McpSchema.CallToolResult busy = refuseIfBusyDescendants(folder);
		if (busy != null) {
			return busy;
		}
		releaseDescendants(folder);
		DomainFolder moved = folder.moveTo(getOrCreateFolder(data, dest));
		return Results.ok("Moved to " + moved.getPathname());
	}

	/** Non-null refusal when any file under {@code folder} has a background task running. */
	private static McpSchema.CallToolResult refuseIfBusyDescendants(DomainFolder folder) {
		List<String> busy = new ArrayList<>();
		collectBusy(folder, busy);
		if (busy.isEmpty()) {
			return null;
		}
		return Results.error("A background task (e.g. analysis) is still running on:\n  " +
			String.join("\n  ", busy) + "\nwait for it to finish and retry.");
	}

	private static void collectBusy(DomainFolder folder, List<String> busy) {
		for (DomainFolder sub : folder.getFolders()) {
			collectBusy(sub, busy);
		}
		for (DomainFile file : folder.getFiles()) {
			if (file.isBusy()) {
				busy.add(file.getPathname());
			}
		}
	}

	/**
	 * Drop our cached handles on every program under {@code folder}. {@link ProjectContext}
	 * keys its cache by exact project path, so a folder rename/move would otherwise strand
	 * entries under paths that no longer exist.
	 */
	private void releaseDescendants(DomainFolder folder) {
		for (DomainFolder sub : folder.getFolders()) {
			releaseDescendants(sub);
		}
		for (DomainFile file : folder.getFiles()) {
			context.release(file.getPathname());
		}
	}

	private static String describeContents(DomainFolder folder) {
		int files = folder.getFiles().length;
		int folders = folder.getFolders().length;
		return files + " file(s), " + folders + " subfolder(s)";
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
