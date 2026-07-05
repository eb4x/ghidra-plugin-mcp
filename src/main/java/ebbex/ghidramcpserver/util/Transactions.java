package ebbex.ghidramcpserver.util;

import java.lang.reflect.InvocationTargetException;
import java.util.concurrent.Callable;
import java.util.concurrent.atomic.AtomicReference;

import javax.swing.SwingUtilities;

import ghidra.program.model.listing.Program;
import io.modelcontextprotocol.spec.McpSchema;

/** The single write path: run a mutation on the Swing EDT inside a transaction. */
public final class Transactions {

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
		AtomicReference<McpSchema.CallToolResult> out = new AtomicReference<>();
		Runnable task = () -> {
			int tx = program.startTransaction(txName);
			boolean commit = false;
			try {
				String message = body.call();
				out.set(Results.ok(message));
				commit = true;
			}
			catch (Exception e) {
				String detail = e.getMessage() != null ? e.getMessage() : e.toString();
				out.set(Results.error(txName + " failed: " + detail));
			}
			finally {
				program.endTransaction(tx, commit);
			}
		};

		try {
			if (SwingUtilities.isEventDispatchThread()) {
				task.run();
			}
			else {
				SwingUtilities.invokeAndWait(task);
			}
		}
		catch (InterruptedException e) {
			Thread.currentThread().interrupt();
			return Results.error(txName + " interrupted");
		}
		catch (InvocationTargetException e) {
			return Results.error(txName + " failed: " + e.getCause());
		}
		return out.get();
	}
}
