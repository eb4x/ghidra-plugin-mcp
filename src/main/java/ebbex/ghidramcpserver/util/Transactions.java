package ebbex.ghidramcpserver.util;

import java.util.concurrent.Callable;
import java.util.concurrent.TimeoutException;

import javax.swing.SwingUtilities;

import ghidra.framework.model.TransactionInfo;
import ghidra.program.model.listing.Program;
import ghidra.util.SystemUtilities;
import io.modelcontextprotocol.spec.McpSchema;

/** The single write path: run a mutation on the Swing EDT inside a transaction. */
public final class Transactions {

	/**
	 * Bound for one edit. Enormously generous next to the milliseconds an edit actually takes —
	 * the point is not to police slow work but to make sure a wedged event thread is reported
	 * instead of waited on forever. Bulk callers pass their own; see {@link #modify(Program,
	 * String, long, Callable)}.
	 */
	private static final long DEFAULT_TIMEOUT_MS = 60_000;

	/**
	 * How long to wait for another transaction on the program to close before opening ours
	 * inside it. Auto-analysis after a signature change is usually over in well under this;
	 * a longer one is joined rather than waited on (see {@link #modify}).
	 */
	private static final long SETTLE_MS = 1_500;

	private Transactions() {
	}

	/**
	 * Run {@code body} on the EDT wrapped in a Ghidra transaction named {@code txName}.
	 * The transaction is committed only if the body returns normally; any exception
	 * rolls it back and is reported as a tool error. The body returns the success
	 * message shown to the caller.
	 */
	public static McpSchema.CallToolResult modify(Program program, String txName,
			Callable<String> body) {
		return modify(program, txName, DEFAULT_TIMEOUT_MS, body);
	}

	/**
	 * As {@link #modify(Program, String, Callable)}, with an explicit bound on how long to wait
	 * for the event thread. For bulk work that legitimately holds the transaction for a long time
	 * — a whole-program {@code migrate} is thousands of edits in one transaction — where the
	 * single-edit default would report a timeout on a migration that is merely working.
	 *
	 * <p><b>Ghidra transactions nest per program, not per thread.</b> If anything else holds a
	 * transaction open on this program when ours starts — the GUI's auto-analysis, which a
	 * signature or variable edit a moment earlier scheduled on a background thread, wraps its
	 * whole run in one ({@code BackgroundCommandTask}) — ours becomes an <em>entry</em> inside it.
	 * Entries cannot be rolled back on their own: ending one with {@code commit=false} marks the
	 * enclosing transaction aborted, and when that finally ends Ghidra discards everything since
	 * the last checkpoint — the analysis's work and every other entry, including edits this
	 * server had already reported as "ok" (a 36-edit batch kept two). So this method first gives
	 * an open transaction a short chance to close, and if it must join one, a failing body is
	 * reported but <em>not</em> rolled back; the message says so. Only an outermost transaction
	 * of our own is rolled back on failure.
	 */
	public static McpSchema.CallToolResult modify(Program program, String txName, long timeoutMs,
			Callable<String> body) {
		awaitNoOpenTransaction(program);
		Callable<McpSchema.CallToolResult> task = () -> {
			TransactionInfo enclosing = program.getCurrentTransactionInfo();
			int tx = program.startTransaction(txName);
			boolean commit = false;
			try {
				String message = body.call();
				commit = true;
				return Results.ok(message);
			}
			catch (Exception e) {
				String detail = e.getMessage() != null ? e.getMessage() : e.toString();
				if (enclosing == null) {
					return Results.error(txName + " failed: " + detail);
				}
				// Keep the entry: aborting it would take the enclosing transaction down with it.
				commit = true;
				return Results.error(txName + " failed: " + detail + "\n" + keptNote(enclosing));
			}
			finally {
				program.endTransaction(tx, commit);
			}
		};

		try {
			return Edt.runNow(task, timeoutMs);
		}
		catch (TimeoutException e) {
			// Returning an error matters beyond the wording: the endpoint skips its auto-save on an
			// error result, which is right here — there is nothing known to save, and the
			// transaction may still be open on the event thread.
			// The transaction is still open on the event thread, so Ghidra's write lock is still
			// held. Observed by forcing this branch: the next edit comes back "Unable to lock due
			// to active transaction". Say so, or an agent reads that cascade as a new mystery
			// rather than as this timeout still unwinding.
			return Results.error(txName + " " + Edt.timeoutAdvice(timeoutMs) +
				" If the edit did land, it is only in memory — run save once the UI is free. Until " +
				"this transaction closes, further writes to this program can also fail with " +
				"\"Unable to lock due to active transaction\"; that is this timeout, not a new " +
				"problem.");
		}
		catch (InterruptedException e) {
			Thread.currentThread().interrupt();
			return Results.error(txName + " interrupted");
		}
		catch (Exception e) {
			// The task above catches everything the body can throw, so this is the residue:
			// an Error, or a failure in the transaction bookkeeping itself.
			return Results.error(txName + " failed: " + e);
		}
	}

	/**
	 * Wait, briefly and off the event thread, for a transaction someone else holds on the
	 * program to close, so that ours gets a checkpoint of its own. Headless Ghidra runs analysis
	 * synchronously on the caller's thread, so there is nothing to wait for there — and a script
	 * calling tools from inside its own transaction would wait out the whole bound for nothing.
	 */
	private static void awaitNoOpenTransaction(Program program) {
		if (SwingUtilities.isEventDispatchThread() || SystemUtilities.isInHeadlessMode()) {
			return;
		}
		long deadline = System.currentTimeMillis() + SETTLE_MS;
		while (program.getCurrentTransactionInfo() != null &&
			System.currentTimeMillis() < deadline) {
			try {
				Thread.sleep(50);
			}
			catch (InterruptedException e) {
				Thread.currentThread().interrupt();
				return;
			}
		}
	}

	private static String keptNote(TransactionInfo enclosing) {
		return "Note: this ran inside the open transaction '" + enclosing.getDescription() +
			"' (Ghidra nests transactions per program), so it was NOT rolled back: rolling back " +
			"an entry aborts the whole enclosing transaction and would discard its other work, " +
			"including earlier edits of this batch. Any partial change this edit made before " +
			"failing is still in place — re-read the target to check.";
	}
}
