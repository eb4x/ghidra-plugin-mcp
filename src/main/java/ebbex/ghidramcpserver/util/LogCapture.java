package ebbex.ghidramcpserver.util;

import java.util.ArrayList;
import java.util.List;

import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.core.LogEvent;
import org.apache.logging.log4j.core.LoggerContext;
import org.apache.logging.log4j.core.appender.AbstractAppender;
import org.apache.logging.log4j.core.config.Configuration;
import org.apache.logging.log4j.core.config.LoggerConfig;
import org.apache.logging.log4j.core.config.Property;

/**
 * Collects what the current thread logs through {@code Msg.*} (INFO and above) while open, so
 * a synchronous run can hand its application.log lines back to the caller instead of leaving
 * them to a follow-up {@code read_log}. Attaches a log4j appender to every configured logger for
 * the duration and detaches it on {@link #close()}; other threads' events are ignored. When
 * Ghidra's logging is not log4j-core (a bare test JVM), nothing is captured.
 */
public final class LogCapture implements AutoCloseable {

	private final List<String> lines = new ArrayList<>();
	private final long threadId = Thread.currentThread().threadId();
	private final LoggerContext context;
	private final AbstractAppender appender;

	public LogCapture() {
		context = LogManager.getContext(false) instanceof LoggerContext c ? c : null;
		if (context == null) {
			appender = null;
			return;
		}
		appender = new AbstractAppender("mcp-capture-" + threadId, null, null, true,
			Property.EMPTY_ARRAY) {
			@Override
			public void append(LogEvent event) {
				if (event.getThreadId() != threadId) {
					return;
				}
				synchronized (lines) {
					lines.add(format(event));
				}
			}
		};
		appender.start();
		Configuration config = context.getConfiguration();
		config.getRootLogger().addAppender(appender, Level.INFO, null);
		for (LoggerConfig logger : config.getLoggers().values()) {
			logger.addAppender(appender, Level.INFO, null);
		}
		context.updateLoggers();
	}

	/** The captured entries in order, each {@code LEVEL (OriginatingClass) message}. */
	public List<String> lines() {
		synchronized (lines) {
			return List.copyOf(lines);
		}
	}

	private static String format(LogEvent event) {
		String logger = event.getLoggerName();
		String origin = logger.substring(logger.lastIndexOf('.') + 1);
		String text = event.getLevel() + " (" + origin + ") " + event.getMessage().getFormattedMessage();
		Throwable thrown = event.getThrown();
		return thrown == null ? text : text + "\n  " + thrown;
	}

	@Override
	public void close() {
		if (context == null) {
			return;
		}
		Configuration config = context.getConfiguration();
		config.getRootLogger().removeAppender(appender.getName());
		for (LoggerConfig logger : config.getLoggers().values()) {
			logger.removeAppender(appender.getName());
		}
		context.updateLoggers();
		appender.stop();
	}
}
