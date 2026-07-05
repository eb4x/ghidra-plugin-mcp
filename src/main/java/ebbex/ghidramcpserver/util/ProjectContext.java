package ebbex.ghidramcpserver.util;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.locks.ReentrantLock;

import ghidra.framework.main.AppInfo;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.Project;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

/**
 * Resolves programs by their project path and manages their open lifetime.
 *
 * <p>The active project comes from {@link AppInfo#getActiveProject()}, so no
 * project open/close tracking is needed. Programs are opened on demand (shared
 * with any CodeBrowser that has the same file open), cached by path for the
 * duration of the server, and released when the plugin is disposed. Writes are
 * persisted with {@link #save(String)}.
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

	/** Persist edits made to the program at {@code path} back to the project. */
	public synchronized void save(String path) throws Exception {
		Program program = openByPath.get(path);
		if (program != null && !program.isClosed()) {
			program.getDomainFile().save(TaskMonitor.DUMMY);
		}
	}

	/** Drop this context's hold on one program (e.g. before deleting/moving its file). */
	public synchronized void release(String path) {
		Program program = openByPath.remove(path);
		if (program != null) {
			decompilers.release(program);
			if (!program.isClosed()) {
				program.release(consumer);
			}
		}
		writeLocks.remove(path);
	}

	/** Release every program this context has opened (called on plugin dispose). */
	public synchronized void releaseAll() {
		for (Program program : openByPath.values()) {
			try {
				decompilers.release(program);
				program.release(consumer);
			}
			catch (Exception e) {
				// best effort on shutdown
			}
		}
		openByPath.clear();
	}
}
