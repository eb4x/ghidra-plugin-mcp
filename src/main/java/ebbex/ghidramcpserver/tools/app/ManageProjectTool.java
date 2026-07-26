package ebbex.ghidramcpserver.tools.app;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeoutException;
import java.util.stream.Collectors;

import ebbex.ghidramcpserver.ApplicationLevelTool;
import ebbex.ghidramcpserver.util.Args;
import ebbex.ghidramcpserver.util.Edt;
import ebbex.ghidramcpserver.util.ProjectContext;
import ebbex.ghidramcpserver.util.Results;
import ebbex.ghidramcpserver.util.Schemas;
import ghidra.framework.data.DefaultProjectData;
import ghidra.framework.main.AppInfo;
import ghidra.framework.main.FrontEndTool;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.Project;
import ghidra.framework.model.ProjectListener;
import ghidra.framework.model.ProjectLocator;
import ghidra.framework.model.ProjectManager;
import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginTool;
import ghidra.util.Msg;
import ghidra.util.NotOwnerException;
import ghidra.util.SystemUtilities;
import ghidra.util.exception.AssertException;
import ghidra.util.exception.NotFoundException;
import ghidra.util.task.TaskMonitor;
import io.modelcontextprotocol.spec.McpSchema;

/**
 * Open, close, and list Ghidra projects — the lifecycle every other tool depends on.
 *
 * <p>Exists because a project whose directory is moved or renamed underneath a running Ghidra
 * leaves the server silently half-working: cached listings keep answering while every read of
 * file <em>contents</em> fails, and nothing else on the application-level surface can re-point
 * the instance. Restarting made it worse, because Ghidra reopens the last project through the
 * same stale locator — hence {@code setLastOpenedProject(null)} on close.
 *
 * <p><b>Both mutating ops must touch Swing.</b> {@code FrontEndTool.setActiveProject} rebuilds
 * the Front End's panels directly, {@code openProject(…, doRestore=true, …)} relaunches the
 * saved CodeBrowsers and reopens their programs, and {@code Project.close()} disposes those
 * tools' windows. So each runs in a single hop on the EDT, exactly as
 * {@code GhidraRun.doOpenProject} does.
 *
 * <p><b>The hazard that shapes the whole class: a modal dialog raised inside our own call.</b>
 * Ghidra reports project-open failures with {@code Msg.showError}, which pumps a nested event
 * loop — so the call does not return until a human clicks. Every precheck below exists to make
 * a given dialog unreachable, and {@link Edt#runNow} bounds the wait so the MCP call returns even
 * when one appears anyway. Three residual sources cannot be prechecked away: a filesystem
 * failure mid-open, a corrupt {@code projectState}, and a prompt from a <em>restored</em>
 * CodeBrowser (a required program upgrade, a missing language). On a timeout the instance's
 * state is genuinely indeterminate and the caller is told to look at the Ghidra window.
 */
public class ManageProjectTool implements ApplicationLevelTool {

	private static final List<String> OPS = List.of("open", "close", "list_recent");
	private static final List<String> ON_DIRTY = List.of("refuse", "save", "discard");

	/** Restoring a project's tools (CodeBrowsers plus their programs) legitimately takes seconds. */
	private static final long OPEN_TIMEOUT_MS = 60_000;
	private static final long CLOSE_TIMEOUT_MS = 30_000;
	private static final long SAVE_TIMEOUT_MS = 30_000;

	private final ProjectContext context;

	/**
	 * Application-level tools get no lock from the endpoint, so two concurrent calls would both
	 * clear the guards. One tool instance is registered, so this makes each guard sequence atomic
	 * against itself.
	 */
	private final Object lifecycleLock = new Object();

	public ManageProjectTool(ProjectContext context) {
		this.context = context;
	}

	@Override
	public String name() {
		return "manage_project";
	}

	@Override
	public String description() {
		return "Open, close, or list Ghidra projects. op=list_recent shows the projects Ghidra " +
			"knows with their path/name ready to pass to op=open, marking any whose storage is " +
			"[MISSING] or [LOCKED]; it works with no project open. op=open opens 'path' + 'name' " +
			"and makes it active — it refuses while another project is open AND reachable (close " +
			"that one first), but WILL replace one whose directory has been moved, renamed or " +
			"deleted, which is the state it exists to recover from. op=close discards every " +
			"CodeBrowser without asking, so it refuses while any file is busy or unsaved; pass " +
			"on_dirty=save to write them first (the close aborts if a save fails) or " +
			"on_dirty=discard to lose them. Both open and close need the Ghidra GUI. Either one " +
			"drops every cached program handle, so program tools re-resolve their paths " +
			"afterwards.";
	}

	@Override
	public Map<String, Object> inputSchema() {
		return Map.of(
			"type", "object",
			"properties", Map.of(
				"op", Schemas.enumProp("What to do", OPS),
				"path", Schemas.stringProp("For op=open: the absolute directory containing " +
					"<name>.gpr, e.g. /home/me/src/viceroy"),
				"name", Schemas.stringProp("For op=open: the project name, e.g. viceroy (a " +
					"trailing '.gpr' is accepted and stripped)"),
				"on_dirty", Schemas.enumProp("For op=close: what to do when open files have " +
					"unsaved changes — refuse (default), save (write them first, aborting the " +
					"close if any save fails), or discard (close and lose them)", ON_DIRTY)),
			"required", List.of("op"));
	}

	@Override
	public boolean isReadOnly() {
		return false;
	}

	/** op=open and op=list_recent must work from a cold start, before any project exists. */
	@Override
	public boolean requiresProject() {
		return false;
	}

	@Override
	public McpSchema.CallToolResult execute(Map<String, Object> args, Project project)
			throws Exception {
		String op = Args.stringArg(args, "op", null);
		if (op == null || !OPS.contains(op)) {
			return Results.error("op must be one of " + OPS);
		}
		return switch (op) {
			case "list_recent" -> listRecent(project);
			case "open" -> {
				synchronized (lifecycleLock) {
					yield open(args, project);
				}
			}
			case "close" -> {
				synchronized (lifecycleLock) {
					yield close(args, project);
				}
			}
			default -> Results.error("unhandled op " + op);
		};
	}

	// ---- op=open ----

	/**
	 * Guards run in an order chosen so no modal dialog is reachable, and so each
	 * {@link ProjectLocator} file accessor is only used after {@code exists()} (its javadoc
	 * requires that — the platform checks come first). Everything is off the EDT except the
	 * final hop.
	 */
	private McpSchema.CallToolResult open(Map<String, Object> args, Project project) {
		// 1. A Front End must exist: AppInfo.getFrontEndTool() throws without one.
		FrontEndTool frontEnd = frontEnd();
		if (frontEnd == null) {
			return Results.error("op=open needs the Ghidra GUI Front End, which is not running " +
				"(headless, or the project window is still starting).");
		}
		ProjectManager manager = frontEnd.getProjectManager();
		if (manager == null) {
			return Results.error("The Ghidra Front End has no project manager; cannot open a " +
				"project.");
		}

		// 2. Arguments. A blank path is not a harmless default: ProjectLocator silently
		// substitutes Ghidra's temp directory for one, which would open something the caller
		// never named. And its constructor dereferences the name before null-checking it.
		String name = Args.stringArg(args, "name", null);
		if (name == null || name.isBlank()) {
			return Results.error("name is required for op=open: the project name, e.g. viceroy " +
				"for viceroy.gpr (a trailing '.gpr' is accepted). Use op=list_recent to see the " +
				"projects Ghidra knows.");
		}
		String path = Args.stringArg(args, "path", null);
		if (path == null || path.isBlank()) {
			return Results.error("path is required for op=open: the absolute directory that " +
				"contains " + name + ".gpr. (A blank path would silently mean Ghidra's temp " +
				"directory, so it is refused rather than guessed.)");
		}
		ProjectLocator locator;
		try {
			locator = new ProjectLocator(path, name);
		}
		catch (IllegalArgumentException e) {
			return Results.error("Invalid project location (path '" + path + "', name '" + name +
				"'): " + e.getMessage() + " — the path must be absolute, and the name may not " +
				"contain path separators.");
		}

		// 3+4. The target's storage must be reachable and complete. Skipping this is what turns
		// an open failure into a modal "Open Project Failed!" dialog.
		String problem = ProjectContext.storageProblem(locator);
		if (problem != null) {
			return Results.error("Cannot open '" + name + "': " + problem +
				". Use op=list_recent to see the projects Ghidra knows.");
		}
		// A read-only marker file raises its own modal dialog (ReadOnlyException extends
		// IOException, and Ghidra can only open a project for update).
		File marker = locator.getMarkerFile();
		if (!marker.canWrite()) {
			return Results.error("Cannot open '" + name + "': " + marker + " is not writable, " +
				"and Ghidra only opens projects for update. Fix its permissions and retry.");
		}

		// 5. A locked target would raise the modal "Project Locked - Delete Lock?" prompt, which
		// this server cannot answer — so answer it here, in text.
		if (DefaultProjectData.isLocked(locator)) {
			return Results.error("Project '" + name + "' is locked: another Ghidra instance has " +
				"it open. Close it there. If no Ghidra is running, the lock is stale — delete " +
				locator.getProjectLockFile() + " and retry.");
		}

		// 6. Something already open? Consult the manager's own field first: that is what
		// openProject() guards on (it throws LockException when set), and it can disagree with
		// AppInfo.getActiveProject() if a previous open half-failed.
		Project current = manager.getActiveProject() != null ? manager.getActiveProject() : project;
		ProjectLocator currentLocator = current == null ? null : current.getProjectLocator();
		if (current != null && ProjectContext.storageProblem(currentLocator) == null) {
			if (locator.equals(currentLocator)) {
				return Results.ok("Project '" + current.getName() + "' is already open at " +
					currentLocator.getLocation() + " — nothing to do.");
			}
			return Results.error("Project '" + current.getName() + "' is already open at " +
				currentLocator.getLocation() + " and its storage is reachable — refusing to " +
				"switch silently. Run op=close first (it refuses while anything is unsaved).");
		}

		// 7. Replace a stranded project. No dirty check: its changes cannot be written back
		// anyway, so they are counted and reported instead of being quietly dropped.
		String replaced = null;
		if (current != null) {
			replaced = closeStranded(frontEnd, current, currentLocator);
			if (manager.getActiveProject() != null) {
				return Results.error("Could not close the stranded project '" + current.getName() +
					"' (" + replaced + "), so nothing was opened.");
			}
		}

		// 8. The open itself, in one bounded hop on the EDT.
		try {
			String opened = Edt.runNow(() -> {
				Project fresh = manager.openProject(locator, true, false);
				frontEnd.setActiveProject(fresh);
				return fresh.getName();
			}, OPEN_TIMEOUT_MS);
			return Results.ok((replaced != null ? replaced + "\n" : "") +
				"Opened project '" + opened + "' at " + locator.getLocation() +
				". It is now the active project; list_files shows its contents.");
		}
		catch (Exception e) {
			return Results.error(describeOpenFailure(e, locator, replaced));
		}
	}

	/**
	 * Close a project whose storage is unreachable, or which the project manager still holds
	 * while {@code AppInfo} does not. Returns a sentence describing what happened, for the
	 * caller's benefit — this is a recovery path, so it reports rather than refuses.
	 */
	private String closeStranded(FrontEndTool frontEnd, Project stranded, ProjectLocator locator) {
		String name = stranded.getName();
		int unsaved = countChanged(stranded);
		context.releaseAll();
		try {
			Edt.runNow(() -> {
				closeAndNotify(frontEnd, stranded);
				return null;
			}, CLOSE_TIMEOUT_MS);
		}
		catch (Exception e) {
			// DefaultProject.close() nulls the manager's project before it can fail on storage,
			// so a throwing close usually still leaves the manager openable; the caller re-checks.
			return "closing the stranded project '" + name + "' reported: " + describe(e);
		}
		return "Closed stranded project '" + name + "' (" +
			(locator == null ? "no location" : locator.getLocation()) + " is unreachable)" +
			(unsaved > 0 ? "; " + unsaved + " file(s) held unsaved changes that could not be " +
				"written back, because its storage is gone" : "") + ".";
	}

	// ---- op=close ----

	private McpSchema.CallToolResult close(Map<String, Object> args, Project project) {
		FrontEndTool frontEnd = frontEnd();
		if (frontEnd == null) {
			return Results.error("op=close needs the Ghidra GUI Front End, which is not running " +
				"(headless, or the project window is still starting).");
		}
		Project open = project != null ? project : frontEnd.getProjectManager().getActiveProject();
		if (open == null) {
			return Results.ok("No project is open — nothing to close.");
		}
		String onDirty = Args.stringArg(args, "on_dirty", "refuse");
		if (!ON_DIRTY.contains(onDirty)) {
			return Results.error("on_dirty must be one of " + ON_DIRTY);
		}
		String name = open.getName();

		// 1. Busy is never overridable: Project.close() disposes every running tool hard, so
		// closing under a live analysis would kill it mid-transaction.
		List<String> busy = new ArrayList<>();
		for (DomainFile file : open.getOpenData()) {
			if (file.isBusy()) {
				busy.add(file.getPathname() + "  (a background task is still running on it)");
			}
		}
		for (PluginTool running : open.getToolManager().getRunningTools()) {
			if (running.isExecutingCommand()) {
				busy.add("tool '" + running.getName() + "'  (executing a command)");
			}
		}
		if (!busy.isEmpty()) {
			return Results.error("Refusing to close '" + name + "' — work is still in flight on:" +
				bullets(busy) + "\nWait for it to finish and retry.");
		}

		// 2. Our own writes. Ghidra's checks above can't see a short MCP write on another HTTP
		// thread, and releasing that program would close it under an open transaction.
		List<String> writing = context.pathsBeingWritten();
		if (!writing.isEmpty()) {
			return Results.error("Refusing to close '" + name + "' — this server has a write in " +
				"flight on:" + bullets(writing) + "\nRetry in a moment.");
		}

		// 3. Unsaved changes. getOpenData() is the same set Ghidra's own close path saves: the
		// project's files plus any viewed projects' and transients'.
		List<DomainFile> changed = new ArrayList<>();
		for (DomainFile file : open.getOpenData()) {
			if (file.isChanged()) {
				changed.add(file);
			}
		}
		if ("refuse".equals(onDirty) && !changed.isEmpty()) {
			return Results.error("Refusing to close '" + name + "' — " + changed.size() +
				" file(s) have unsaved changes:" +
				bullets(changed.stream()
						.map(f -> f.getPathname() +
							(f.canSave() ? "" : "  [not saveable: read-only, or versioned and " +
								"not checked out]") +
							"  (held by: " + describeConsumers(f) + ")")
						.toList()) +
				"\nPass on_dirty=save to write them first, or on_dirty=discard to close anyway " +
				"and lose them. Closing disposes every CodeBrowser without asking.");
		}
		if ("save".equals(onDirty)) {
			List<String> failed = saveAll(changed);
			if (!failed.isEmpty()) {
				// Never fall through to closing: that would silently discard, which is what
				// on_dirty=discard is for. Nothing was released or closed, so this is retryable.
				return Results.error("Nothing was closed — " + failed.size() +
					" file(s) could not be saved:" + bullets(failed) +
					"\nFix those, or pass on_dirty=discard to close and lose the changes.");
			}
		}

		// 4. Drop our handles first: a project still holding open domain objects defers its
		// dispose(), and with it the release of its .lock file.
		int released = context.releaseAll();

		// 5. The close itself, in one bounded hop on the EDT.
		try {
			Edt.runNow(() -> {
				closeAndNotify(frontEnd, open);
				return null;
			}, CLOSE_TIMEOUT_MS);
		}
		catch (TimeoutException e) {
			// Its message is null, so it must be spelled out rather than passed to describe().
			return Results.error("Closing '" + name + "' " +
				Edt.timeoutAdvice(CLOSE_TIMEOUT_MS) +
				" Here that means the project may or may not have closed: call " +
				"get_application_info to see. This server has already released its cached " +
				"program handles either way.");
		}
		catch (Exception e) {
			return Results.error("Closing '" + name + "' failed: " + describe(e) +
				" — call get_application_info to see the resulting state.");
		}

		// 6. Don't let the next Ghidra start silently reopen it. This is what made the original
		// stranded-project incident survive a restart.
		frontEnd.getProjectManager().setLastOpenedProject(null);

		String fate = changed.isEmpty() ? ""
				: "save".equals(onDirty) ? " (saved " + changed.size() + " file(s) first)"
						: " (discarded unsaved changes in " + changed.size() + " file(s))";
		return Results.ok("Closed project '" + name + "'" + fate +
			(released > 0 ? "; released " + released + " cached program handle(s)" : "") +
			". No project is open now — use op=open, or op=list_recent to see what Ghidra knows.");
	}

	/**
	 * Save every changed file, bounded. Returns "path — reason" for each failure; empty on
	 * success. Runs on the calling thread: this is blocking database IO and must never be on the
	 * EDT.
	 *
	 * <p>The retry mirrors {@code ProjectContext.saveSettled}, which cannot be reused here
	 * because it is {@code Program}-typed while {@code getOpenData()} yields {@code DomainFile}s
	 * and CodeBrowser-held programs are not in our cache. Its reason applies unchanged: a save
	 * while Ghidra's auto-analysis holds a transaction fails the lock with "Unable to lock due to
	 * active transaction" even though the edits are already committed in memory.
	 */
	private static List<String> saveAll(List<DomainFile> changed) {
		List<String> failed = new ArrayList<>();
		for (DomainFile file : changed) {
			if (!file.canSave()) {
				// Read-only, or versioned and not checked out — no amount of retrying helps.
				failed.add(file.getPathname() +
					" — not saveable (read-only, or versioned and not checked out)");
				continue;
			}
			long deadline = System.currentTimeMillis() + SAVE_TIMEOUT_MS;
			String why = null;
			while (true) {
				if (file.isBusy()) {
					// Refused in step 1 already; this covers the race.
					why = "busy — a background task is still running on it";
				}
				else {
					try {
						file.save(TaskMonitor.DUMMY);
						why = null;
						break;
					}
					catch (IOException e) {
						// Typically the active-transaction lock failure; retry until the deadline.
						why = e.getMessage();
					}
					catch (Exception e) {
						why = describe(e);
						break;
					}
				}
				if (System.currentTimeMillis() >= deadline) {
					break;
				}
				try {
					Thread.sleep(100);
				}
				catch (InterruptedException e) {
					Thread.currentThread().interrupt();
					why = "interrupted while waiting to save";
					break;
				}
			}
			if (why != null) {
				failed.add(file.getPathname() + " — " + why);
			}
		}
		return failed;
	}

	// ---- op=list_recent ----

	private McpSchema.CallToolResult listRecent(Project project) {
		ProjectManager manager = null;
		FrontEndTool frontEnd = frontEnd();
		if (frontEnd != null) {
			manager = frontEnd.getProjectManager();
		}
		if (manager == null && project != null) {
			// Headless (analyzeHeadless, the smoke script): the project knows the manager that
			// opened it, so this op still answers without a Front End.
			manager = project.getProjectManager();
		}
		if (manager == null) {
			return Results.error("Cannot list recent projects: no Ghidra Front End is running " +
				"and no project is open, so there is no project manager to ask.");
		}

		StringBuilder out = new StringBuilder();
		out.append("Active: ")
				.append(project == null ? "(none open)"
						: project.getName() + "  (" + project.getProjectLocator().getLocation() +
							")")
				.append('\n');
		ProjectLocator[] recent = manager.getRecentProjects();
		if (recent.length == 0) {
			return Results.ok(out.append("\nRecent projects: (none)").toString());
		}
		out.append("\nRecent projects, most recent first — pass path and name to op=open:\n");
		for (ProjectLocator locator : recent) {
			out.append("  path=")
					.append(locator.getLocation())
					.append(" name=")
					.append(locator.getName())
					.append(marks(locator, project))
					.append('\n');
		}
		out.append(Results.paginationFooter(recent.length, 0, recent.length));
		return Results.ok(out.toString());
	}

	/**
	 * Status marks. Ghidra validates this list only once, when it builds its project manager, so
	 * an entry can have gone stale since — which is the very failure this tool exists to recover
	 * from, and worth flagging rather than leaving to a failed open.
	 */
	private static String marks(ProjectLocator locator, Project active) {
		StringBuilder marks = new StringBuilder();
		if (active != null && locator.equals(active.getProjectLocator())) {
			marks.append("  [OPEN]");
		}
		String problem = ProjectContext.storageProblem(locator);
		if (problem != null) {
			marks.append("  [MISSING — ").append(problem).append("]");
		}
		else if (DefaultProjectData.isLocked(locator)) {
			marks.append("  [LOCKED — in use by another Ghidra]");
		}
		return marks.toString();
	}

	// ---- shared helpers ----

	/** The Front End, or null when there isn't one (headless, or still starting). */
	private static FrontEndTool frontEnd() {
		if (SystemUtilities.isInHeadlessMode()) {
			return null;
		}
		try {
			return AppInfo.getFrontEndTool();
		}
		catch (AssertException e) {
			// "Cannot use AppInfo without a Front End running"
			return null;
		}
	}

	/**
	 * Close a project the way Ghidra's own dialog-free path does — {@code FileActionManager}'s
	 * delete-project branch is exactly {@code close()}, {@code fireProjectClosed()},
	 * {@code setActiveProject(null)}.
	 *
	 * <p>The middle step is not optional, and leaving it out fails in a way that only shows up on
	 * the <em>next</em> open: project listeners hold the project they were handed until they are
	 * told it closed, and {@code RecoverySnapshotMgrPlugin.projectOpened} throws
	 * "Unexpected - two or more projects active" when it is handed a second one. Ghidra fires this
	 * through a package-private hook, so the listeners are reached here as plugins instead.
	 * Listeners that are not plugins are missed — in practice the version-history and checkouts
	 * dialogs, which the user has to have open, and which unregister themselves when dismissed.
	 *
	 * <p>Each notification is guarded: unlike Ghidra's own loop, one listener throwing must not
	 * strand the rest, because by this point the project is already closed.
	 *
	 * <p>Must run on the Swing thread.
	 */
	private static void closeAndNotify(FrontEndTool frontEnd, Project project) {
		project.close();
		for (Plugin plugin : frontEnd.getManagedPlugins()) {
			if (plugin instanceof ProjectListener listener) {
				try {
					listener.projectClosed(project);
				}
				catch (Exception e) {
					Msg.error(ManageProjectTool.class,
						"project listener " + plugin.getName() + " failed on close", e);
				}
			}
		}
		frontEnd.setActiveProject(null);
	}

	/** Files with in-memory changes. Reads no storage, so it is safe on a stranded project. */
	private static int countChanged(Project project) {
		int changed = 0;
		try {
			for (DomainFile file : project.getOpenData()) {
				if (file.isChanged()) {
					changed++;
				}
			}
		}
		catch (Exception e) {
			// A project this broken can fail even here; the count is a courtesy, not a result.
		}
		return changed;
	}

	/** Names of whoever holds a file open, so 'unsaved' errors say where to look. */
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

	private static String bullets(List<String> lines) {
		return "\n  " + String.join("\n  ", lines);
	}

	/**
	 * Turn what {@code openProject} can throw into something the caller can act on. Every case
	 * except a mid-open filesystem failure is pre-empted by a guard above, so reaching most of
	 * these means a race — say which, and whether Ghidra also put up a dialog.
	 */
	private static String describeOpenFailure(Exception e, ProjectLocator locator, String replaced) {
		String prefix = replaced != null ? replaced + "\nThe open then failed: " : "";
		String name = locator.getName();
		if (e instanceof TimeoutException) {
			return prefix + "opening '" + name + "' " + Edt.timeoutAdvice(OPEN_TIMEOUT_MS) +
				" Here the dialog is most likely a restored CodeBrowser's own prompt (a required " +
				"program upgrade, a missing language), which no precheck can pre-empt. Call " +
				"get_application_info afterwards to see which project ended up open.";
		}
		if (e instanceof InterruptedException) {
			Thread.currentThread().interrupt();
			return prefix + "interrupted while opening '" + name + "'.";
		}
		if (e instanceof NotFoundException) {
			return prefix + "'" + name + "' does not exist: " + describe(e);
		}
		if (e instanceof NotOwnerException) {
			return prefix + "'" + name + "' is owned by another user: " + describe(e) +
				" Ghidra only opens your own projects.";
		}
		if (e instanceof IOException) {
			// Includes ReadOnlyException. Ghidra reports these with Msg.showError, so a dialog
			// is up in the GUI as well.
			return prefix + "could not open '" + name + "': " + describe(e) +
				" Ghidra also raised an error dialog for this — dismiss it in the Ghidra window.";
		}
		// LockException and the rest carry usable text; it may be HTML (the lock message is).
		return prefix + "could not open '" + name + "': " + describe(e) +
			" If no other Ghidra is running, a stale lock at " + locator.getProjectLockFile() +
			" can be deleted.";
	}

	/**
	 * An exception's message as one line of plain text.
	 *
	 * <p>Ghidra writes some of these for a dialog rather than a log — the project-lock failure
	 * message is HTML. {@code HTMLUtilities.fromHTML} is not usable here to undo that: it renders
	 * through a {@code JLabel} and so asserts it is on the Swing thread, which would turn a
	 * reportable failure into a thread-assertion failure on the HTTP thread this runs on. Strip
	 * the markup directly instead, and flatten the result so a multi-line message can't break up
	 * a bulleted list it is embedded in.
	 */
	private static String describe(Exception e) {
		String message = e.getMessage();
		if (message == null || message.isBlank()) {
			return e.toString();
		}
		return message.replaceAll("(?i)<br\\s*/?>|</p>", " ")
				.replaceAll("<[^>]+>", "")
				.replace("&nbsp;", " ")
				.replace("&amp;", "&")
				.replace("&lt;", "<")
				.replace("&gt;", ">")
				.replaceAll("\\s+", " ")
				.trim();
	}
}
