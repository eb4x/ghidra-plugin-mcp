package ebbex.ghidramcpserver.util;

import java.util.concurrent.Callable;
import java.util.concurrent.TimeoutException;

import ghidra.program.model.listing.Program;
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
	 */
	public static McpSchema.CallToolResult modify(Program program, String txName, long timeoutMs,
			Callable<String> body) {
		Callable<McpSchema.CallToolResult> task = () -> {
			int tx = program.startTransaction(txName);
			boolean commit = false;
			try {
				String message = body.call();
				commit = true;
				return Results.ok(message);
			}
			catch (Exception e) {
				String detail = e.getMessage() != null ? e.getMessage() : e.toString();
				return Results.error(txName + " failed: " + detail);
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
}
