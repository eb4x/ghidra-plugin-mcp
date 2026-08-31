package ebbex.ghidramcpserver.util;

import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;

import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.program.model.listing.Program;
import ghidra.program.util.GhidraProgramUtilities;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;

/**
 * The one place auto-analysis is run from. Both {@code analyze} and {@code import
 * analyze=true} queue onto a single background worker, so a bulk import of hundreds of
 * objects is analyzed one after another instead of spawning a thread per program, and a
 * program is never queued twice while its first run is still pending.
 *
 * <p>Analysis runs inside a single transaction (mirroring the headless analyzer; some
 * analyzers NPE without one) and saves the program when it completes, so callers that
 * queue here must not also auto-save ({@code managesSave()}).
 */
public final class Analysis {

	private static final ExecutorService WORKER = Executors.newSingleThreadExecutor(r -> {
		Thread t = new Thread(r, "mcp-analysis-queue");
		t.setDaemon(true);
		return t;
	});

	/** Project paths queued or running, so a second request for the same program is a no-op. */
	private static final Set<String> QUEUED = ConcurrentHashMap.newKeySet();

	private static final AtomicInteger PENDING = new AtomicInteger();

	private Analysis() {
	}

	/**
	 * Queue full auto-analysis of the program. Returns false if it was already queued or
	 * running — the caller should say so rather than promise a second run.
	 */
	public static boolean enqueue(Program program) {
		String key = program.getDomainFile().getPathname();
		if (!QUEUED.add(key)) {
			return false;
		}
		PENDING.incrementAndGet();
		WORKER.execute(() -> {
			try {
				analyze(program);
			}
			finally {
				QUEUED.remove(key);
				PENDING.decrementAndGet();
			}
		});
		return true;
	}

	/** Number of analyses queued or running. */
	public static int pending() {
		return PENDING.get();
	}

	/** Block until the queue drains or the timeout passes; returns true if it drained. */
	public static boolean awaitIdle(long timeoutMillis) throws InterruptedException {
		long deadline = System.currentTimeMillis() + timeoutMillis;
		while (PENDING.get() > 0 && System.currentTimeMillis() < deadline) {
			Thread.sleep(250);
		}
		return PENDING.get() == 0;
	}

	/** Run full auto-analysis synchronously on the calling thread, then save. */
	public static void analyze(Program program) {
		try {
			AutoAnalysisManager mgr = AutoAnalysisManager.getAnalysisManager(program);
			int txId = program.startTransaction("Auto-analysis");
			try {
				mgr.initializeOptions();
				mgr.reAnalyzeAll(null);
				mgr.startAnalysis(TaskMonitor.DUMMY);
				GhidraProgramUtilities.markProgramAnalyzed(program);
			}
			finally {
				program.endTransaction(txId, true);
			}
			program.getDomainFile().save(TaskMonitor.DUMMY);
			Msg.info(Analysis.class, "MCP: analysis complete for " + program.getName() + " (" +
				program.getFunctionManager().getFunctionCount() + " functions)");
		}
		catch (Exception e) {
			Msg.error(Analysis.class, "MCP: analysis failed for " + program.getName(), e);
		}
	}
}
