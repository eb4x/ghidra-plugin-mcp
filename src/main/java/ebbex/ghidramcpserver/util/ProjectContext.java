package ebbex.ghidramcpserver.util;

import java.io.File;
import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.locks.ReentrantLock;

import ghidra.framework.data.DefaultProjectData;
import ghidra.framework.main.AppInfo;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.Project;
import ghidra.framework.model.ProjectLocator;
import ghidra.program.model.listing.Program;
import ghidra.util.SystemUtilities;
import ghidra.util.task.TaskMonitor;

/**
 * Resolves programs by their project path and manages their open lifetime.
 *
 * <p>The active project comes from {@link AppInfo#getActiveProject()}, which is re-read on
 * every call — nothing here holds a {@link Project}. Programs are opened on demand (shared
 * with any CodeBrowser that has the same file open), cached by path for the duration of the
 * server, and released when the plugin is disposed. Writes are persisted with
 * {@link #save(String)}.
 *
 * <p>The project can be opened and closed underneath us by {@code manage_project}, and the
 * cache is keyed by project path — keys that mean something different, or nothing, in the next
 * project. So every project change must drop the cache wholesale with {@link #releaseAll()}.
 * That is the whole of the invalidation story precisely because no {@code Project} is held
 * here: no listener, no state machine.
 */
public class ProjectContext {

	/** consumer token for reference-counted domain object opens */
	private final Object consumer = this;
	private final Decompilers decompilers;
	private final Map<String, Program> openByPath = new ConcurrentHashMap<>();
	private final Map<String, ReentrantLock> writeLocks = new ConcurrentHashMap<>();

	/** Decompiler pools are tied to open programs, so this context disposes a
	 * program's pool whenever it releases the program. */
	public ProjectContext(Decompilers decompilers) {
		this.decompilers = decompilers;
	}

	public Project project() {
		return AppInfo.getActiveProject();
	}

	/**
	 * Serializes writes (and their save) to a single program path so two concurrent
	 * mutating tool calls can't race on save(); reads never take this lock, and writes
	 * to different programs stay concurrent.
	 */
	public ReentrantLock writeLock(String path) {
		return writeLocks.computeIfAbsent(path, p -> new ReentrantLock());
	}

	/**
	 * Project paths this server currently has a write in flight on. Best effort — a write can
	 * begin the instant after this returns. Ghidra's own {@code DomainFile.isBusy()} and
	 * {@code PluginTool.isExecutingCommand()} can't see a short MCP write on another HTTP
	 * thread, so {@code manage_project op=close} checks this too: {@link #releaseAll()} during
	 * a write would close a program under an open transaction.
	 */
	public List<String> pathsBeingWritten() {
		return writeLocks.entrySet()
				.stream()
				.filter(e -> e.getValue().isLocked())
				.map(Map.Entry::getKey)
				.toList();
	}

	/**
	 * Why the project at {@code locator} cannot be opened (or, for the active project, why its
	 * files can no longer be read), or null when its storage looks healthy.
	 *
	 * <p>Two conditions, in the order Ghidra hits them. Both would otherwise surface as a raw
	 * filesystem error from deep inside the DB layer — a moved project reports its missing
	 * {@code db.NNN.gbf} buffer file, which names a blob no caller can act on.
	 * {@code ProjectLocator.exists()} alone is not enough: it checks the {@code .gpr} marker and
	 * the {@code .rep} directory, not the data directory inside it.
	 *
	 * <p>Kept strictly factual: the same absence means "moved out from under us" for a project
	 * Ghidra already had open and "you named it wrong" for an open target, so the callers that
	 * know which one they are looking at supply that interpretation.
	 */
	public static String storageProblem(ProjectLocator locator) {
		if (locator == null) {
			return "no project location is known";
		}
		if (!locator.exists()) {
			return "there is no " + locator.getName() + ".gpr marker file and " +
				locator.getProjectDir().getName() + " directory at " + locator.getLocation();
		}
		File dir = locator.getProjectDir();
		// DefaultProjectData tries the indexed folder first, then the legacy mangled one, and
		// throws IOException("Project data directory not found") when neither is there.
		boolean data = new File(dir, DefaultProjectData.INDEXED_DATA_FOLDER_NAME).isDirectory() ||
			new File(dir, DefaultProjectData.MANGLED_DATA_FOLDER_NAME).isDirectory();
		if (!data) {
			return "project storage at " + dir + " has no data directory (expected " +
				DefaultProjectData.INDEXED_DATA_FOLDER_NAME + "/ or " +
				DefaultProjectData.MANGLED_DATA_FOLDER_NAME + "/) — it is incomplete, or was " +
				"only partly moved";
		}
		return null;
	}

	/**
	 * Open (or return the cached) program at the given project path, e.g.
	 * {@code /malware.exe} or {@code /unpacked/stage2.bin}.
	 */
	public synchronized Program openProgram(String path) throws Exception {
		Project project = project();
		if (project == null) {
			throw new IllegalStateException("No project is open in Ghidra");
		}
		Program cached = openByPath.get(path);
		if (cached != null && !cached.isClosed()) {
			return cached;
		}
		DomainFile file = project.getProjectData().getFile(path);
		if (file == null) {
			throw new IllegalArgumentException("No file at project path '" + path + "'");
		}
		if (!Program.class.isAssignableFrom(file.getDomainObjectClass())) {
			throw new IllegalArgumentException("'" + path + "' is not a program (" +
				file.getContentType() + ")");
		}
		Program program =
			(Program) file.getDomainObject(consumer, false, false, TaskMonitor.DUMMY);
		openByPath.put(path, program);
		return program;
	}

	/** Short default bound for the auto-save the endpoint runs after each edit. */
	private static final long DEFAULT_SAVE_TIMEOUT_MS = 3000;

	/** Suffix added to a result whose edits applied but whose save was deferred (program busy). */
	public static final String SAVE_DEFERRED_NOTE =
		"(save deferred — program busy; run save when idle)";

	/**
	 * Persist edits made to the program at {@code path}. Returns true if saved, false if the save
	 * was deferred because the program was busy (see {@link #saveSettled}); a missing/closed
	 * program counts as nothing-to-save (true).
	 */
	public synchronized boolean save(String path) throws Exception {
		Program program = openByPath.get(path);
		if (program == null || program.isClosed()) {
			return true;
		}
		return saveSettled(program, DEFAULT_SAVE_TIMEOUT_MS);
	}

	/** Save with the short default bound. */
	public static boolean saveSettled(Program program) throws Exception {
		return saveSettled(program, DEFAULT_SAVE_TIMEOUT_MS);
	}

	/**
	 * Save a program without hanging when it is busy. An edit (rename, signature/variable change)
	 * fires {@code FUNCTION_CHANGED} events that make Ghidra's auto-analysis schedule follow-on
	 * analysis on a background thread holding its own transaction; a save while that transaction is
	 * open fails the lock with "Unable to lock due to active transaction" even though the edits
	 * already committed. Rather than block on <em>all</em> analysis (which can hold the endpoint's
	 * write lock for minutes on a big batch and time the client out), poll the non-throwing
	 * {@link Program#canLock()} probe with a short backoff and save the instant the lock is free.
	 * If the program stays busy past {@code timeoutMillis}, give up and report <em>deferred</em> —
	 * the edits persist in memory and a later save (the {@code save} tool, or the next idle edit)
	 * writes them. Retrying is safe: the lock check fails before any DB mutation, leaving no
	 * partial state. Must run off the Swing EDT.
	 *
	 * @return true if saved, false if deferred (still busy at the deadline)
	 */
	public static boolean saveSettled(Program program, long timeoutMillis) throws Exception {
		DomainFile file = program.getDomainFile();
		program.flushEvents();
		if (SystemUtilities.isInHeadlessMode()) {
			// Headless analysis runs synchronously on this thread — no background transaction races.
			file.save(TaskMonitor.DUMMY);
			return true;
		}
		long deadline = System.currentTimeMillis() + timeoutMillis;
		while (true) {
			program.flushEvents();
			if (program.canLock()) {
				try {
					file.save(TaskMonitor.DUMMY);
					return true;
				}
				catch (IOException raced) {
					// A transaction opened between the probe and the save — fall through and retry.
				}
			}
			if (System.currentTimeMillis() >= deadline) {
				return false;
			}
			Thread.sleep(100);
		}
	}

	/** Drop this context's hold on one program (e.g. before deleting/moving its file). */
	public synchronized void release(String path) {
		releaseProgram(openByPath.remove(path));
		// The cache is keyed by the exact string each caller passed, so the same file can
		// also sit under a variant spelling — match those by their resolved pathname too.
		var it = openByPath.entrySet().iterator();
		while (it.hasNext()) {
			var entry = it.next();
			if (entry.getValue().getDomainFile().getPathname().equals(path)) {
				it.remove();
				writeLocks.remove(entry.getKey());
				releaseProgram(entry.getValue());
			}
		}
		writeLocks.remove(path);
	}

	private void releaseProgram(Program program) {
		if (program != null) {
			decompilers.release(program);
			if (!program.isClosed()) {
				program.release(consumer);
			}
		}
	}

	/**
	 * Release every program this context has opened, and forget the per-path write locks.
	 * Called on plugin dispose, and by {@code manage_project} whenever the project changes
	 * underneath us (open-replace / close).
	 *
	 * <p>Must run <em>before</em> {@code Project.close()}: {@code DefaultProjectData.close()}
	 * returns early while any domain object is still open, deferring its {@code dispose()} — and
	 * the project's {@code .lock} file is only released in {@code dispose()}. Leave programs open
	 * here and the closed project keeps its lock, after which it cannot be reopened.
	 *
	 * <p>Best-effort per program: on a project whose storage has become unreachable the release
	 * itself can fail, and that must not stop the rest.
	 *
	 * @return the number of programs released
	 */
	public synchronized int releaseAll() {
		int released = openByPath.size();
		for (Program program : openByPath.values()) {
			try {
				decompilers.release(program);
				program.release(consumer);
			}
			catch (Exception e) {
				// best effort on shutdown / on unreachable storage
			}
		}
		openByPath.clear();
		writeLocks.clear();
		return released;
	}
}
