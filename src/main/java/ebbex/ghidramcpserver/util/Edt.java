package ebbex.ghidramcpserver.util;

import java.util.concurrent.Callable;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;

import javax.swing.SwingUtilities;

/**
 * The server's single policy for reaching the Swing event thread: post the work, wait with a
 * bound, and report rather than hang if the bound expires.
 *
 * <p>Ghidra work that touches program state or the GUI has to run on the event thread, but this
 * server's callers arrive on HTTP threads that must always get an answer. The two collide because
 * Ghidra raises <em>modal</em> dialogs from paths an agent can provoke — a program-upgrade prompt,
 * a recovery-snapshot question, a plain error dialog — and a modal dialog pumps a nested event
 * loop, so the event thread never returns to our task. Every unbounded wait behind it becomes
 * permanent: the MCP call never answers, with no error and nothing saying a human needs to click
 * something.
 *
 * <p>Deliberately not {@code ghidra.util.Swing.runNow}, whose final barrier has no timeout at all,
 * and whose timed variant falls through to an unbounded {@code invokeAndWait} in a development
 * build — which is what this project builds against. Nor {@code TaskLauncher.launchModal}: callers
 * here are already off the event thread, so it would only add a second unbounded wait and a modal
 * window of its own.
 *
 * <p>A timeout does not cancel the posted task, and cannot: it may be mid-transaction, and
 * abandoning it half-done would be worse than reporting it. It runs to completion once the event
 * thread is free again. So a timeout means <em>unknown outcome</em>, and every message built on one
 * has to say so.
 */
public final class Edt {

	private Edt() {
	}

	/**
	 * Run {@code body} on the Swing event thread and return its result, waiting at most
	 * {@code timeoutMs}. Runs inline when the caller is already on that thread.
	 *
	 * @throws java.util.concurrent.TimeoutException if the bound expires — the task is still
	 *             queued or running, so the outcome is genuinely unknown
	 * @throws Exception whatever {@code body} threw, unwrapped
	 */
	public static <T> T runNow(Callable<T> body, long timeoutMs) throws Exception {
		if (SwingUtilities.isEventDispatchThread()) {
			return body.call();
		}
		CompletableFuture<T> future = new CompletableFuture<>();
		SwingUtilities.invokeLater(() -> {
			try {
				future.complete(body.call());
			}
			catch (Throwable t) {
				future.completeExceptionally(t);
			}
		});
		try {
			return future.get(timeoutMs, TimeUnit.MILLISECONDS);
		}
		catch (ExecutionException e) {
			Throwable cause = e.getCause();
			throw cause instanceof Exception ex ? ex : new RuntimeException(cause);
		}
	}

	/**
	 * The stock explanation for a timeout: what is blocked, that the outcome is unknown, and what
	 * the human has to do. Callers prepend what they were attempting.
	 *
	 * @param timeoutMs the bound that expired, for the message
	 */
	public static String timeoutAdvice(long timeoutMs) {
		return "timed out after " + (timeoutMs / 1000) + "s waiting for Ghidra's UI thread. Most " +
			"likely a modal dialog is waiting for a human in the Ghidra window (a program-upgrade " +
			"prompt, a recovery-snapshot question, an error dialog). Dismiss it there, then " +
			"re-read the target to see what actually happened — the work was not abandoned and " +
			"may still complete. Every other tool that writes will block the same way until the " +
			"dialog is gone.";
	}
}
