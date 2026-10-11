package ebbex.ghidramcpserver.util;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.util.List;

import org.junit.Test;

import generic.test.AbstractGenericTest;
import ghidra.util.Msg;

/**
 * The one-shot analyzer path hands back what the run logged: INFO and above from this thread,
 * nothing from other threads, nothing after the capture closes.
 */
public class LogCaptureTest extends AbstractGenericTest {

	@Test
	public void capturesThisThreadsMessagesWhileOpen() throws Exception {
		Msg.info(this, "before capture");
		List<String> lines;
		try (LogCapture capture = new LogCapture()) {
			Msg.info(this, "RTLink/Plus: Set CS over 73 overlay module(s)");
			Msg.warn(this, "one warning");
			Msg.debug(this, "debug is below the threshold");
			Thread other = new Thread(() -> Msg.info(this, "from another thread"));
			other.start();
			other.join();
			lines = capture.lines();
		}
		Msg.info(this, "after capture");

		assertEquals(lines.toString(), 2, lines.size());
		assertEquals("INFO (LogCaptureTest) RTLink/Plus: Set CS over 73 overlay module(s)",
			lines.get(0));
		assertEquals("WARN (LogCaptureTest) one warning", lines.get(1));
		assertFalse(lines.toString().contains("another thread"));
		assertTrue(lines.toString().contains("Set CS"));
	}
}
