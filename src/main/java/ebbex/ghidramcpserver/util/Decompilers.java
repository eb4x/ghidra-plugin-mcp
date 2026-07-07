package ebbex.ghidramcpserver.util;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Queue;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.Semaphore;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

/**
 * A small pool of {@link DecompInterface}s per program. Each interface is a separate
 * decompiler process, so up to {@code poolSize} functions of the same program can
 * decompile in parallel — a single interface serializes on its synchronized
 * {@code decompileFunction}, which is what bottlenecks a many-agents-one-program
 * fan-out. Each pool grows lazily up to the cap and reuses idle interfaces.
 *
 * <p>{@link DecompileResults} (and the {@code HighFunction} it carries) are a detached
 * snapshot, so callers may keep using them after the interface returns to the pool.
 */
public class Decompilers {

	private final int poolSize;
	private final Map<Program, Pool> pools = new ConcurrentHashMap<>();

	public Decompilers() {
		this(defaultPoolSize());
	}

	public Decompilers(int poolSize) {
		this.poolSize = Math.max(1, poolSize);
	}

	/**
	 * Decompile a function using an interface from the program's pool. Blocks if all
	 * {@code poolSize} interfaces are busy (natural backpressure), then reuses one.
	 */
	public DecompileResults decompile(Program program, Function function, int timeoutSeconds) {
		Pool pool = pools.computeIfAbsent(program, p -> new Pool(p));
		DecompInterface di = pool.checkout();
		try {
			return di.decompileFunction(function, timeoutSeconds, TaskMonitor.DUMMY);
		}
		finally {
			pool.checkin(di);
		}
	}

	/**
	 * Lease a live interface from the program's pool for the duration of {@code body},
	 * then return it to the pool. Unlike {@link #decompile}, the interface stays checked
	 * out while the callback runs — needed by callers that must keep decompiling with the
	 * same interface (e.g. {@code FillOutStructureHelper} recursing into CALLs). Blocks if
	 * all interfaces are busy, same backpressure as {@link #decompile}.
	 */
	public <T> T withInterface(Program program,
			java.util.function.Function<DecompInterface, T> body) {
		Pool pool = pools.computeIfAbsent(program, p -> new Pool(p));
		DecompInterface di = pool.checkout();
		try {
			return body.apply(di);
		}
		finally {
			pool.checkin(di);
		}
	}

	/** Dispose and forget the pool for one program (e.g. when its file is released). */
	public void release(Program program) {
		Pool pool = pools.remove(program);
		if (pool != null) {
			pool.dispose();
		}
	}

	public void dispose() {
		for (Pool pool : pools.values()) {
			pool.dispose();
		}
		pools.clear();
	}

	/** Pool size = half the cores (2..8), overridable with -Dmcp.decompiler.pool=N. */
	private static int defaultPoolSize() {
		String override = System.getProperty("mcp.decompiler.pool");
		if (override != null) {
			try {
				return Integer.parseInt(override.trim());
			}
			catch (NumberFormatException ignored) {
				// fall through to the computed default
			}
		}
		int cores = Runtime.getRuntime().availableProcessors();
		return Math.max(2, Math.min(8, cores / 2));
	}

	private final class Pool {
		private final Program program;
		private final Semaphore permits = new Semaphore(poolSize);
		private final Queue<DecompInterface> idle = new ConcurrentLinkedQueue<>();
		private final List<DecompInterface> all = new ArrayList<>();

		Pool(Program program) {
			this.program = program;
		}

		DecompInterface checkout() {
			permits.acquireUninterruptibly();
			DecompInterface di = idle.poll();
			if (di == null) {
				di = open(program);
				synchronized (all) {
					all.add(di);
				}
			}
			return di;
		}

		void checkin(DecompInterface di) {
			idle.offer(di);
			permits.release();
		}

		void dispose() {
			synchronized (all) {
				for (DecompInterface di : all) {
					try {
						di.dispose();
					}
					catch (Exception ignored) {
						// best effort on shutdown
					}
				}
				all.clear();
			}
			idle.clear();
		}
	}

	private static DecompInterface open(Program program) {
		DecompInterface di = new DecompInterface();
		DecompileOptions options = new DecompileOptions();
		options.grabFromProgram(program);
		di.setOptions(options);
		di.toggleCCode(true);
		di.toggleSyntaxTree(true);
		di.setSimplificationStyle("decompile");
		if (!di.openProgram(program)) {
			String message = di.getLastMessage();
			di.dispose();
			throw new IllegalStateException("Failed to open decompiler: " + message);
		}
		return di;
	}
}
