package ebbex.ghidramcpserver.util;

import java.io.InputStream;
import java.util.Properties;

/**
 * The build stamp Gradle writes into {@code mcpserver-build.properties} (git commit,
 * {@code +dirty} when the tree had uncommitted changes, and the build time). Lets a
 * client ask the running server which build it is talking to instead of inferring it
 * from restart choreography. A classpath without the resource (e.g. classes run
 * straight from an IDE) reports {@code unstamped}.
 */
public final class BuildInfo {

	private static final String RESOURCE = "/mcpserver-build.properties";
	private static final String DESCRIPTION = load();

	private BuildInfo() {
	}

	/** One-line build identity, e.g. {@code git 146750a+dirty, built 2026-07-12 11:02:03 UTC}. */
	public static String describe() {
		return DESCRIPTION;
	}

	private static String load() {
		try (InputStream in = BuildInfo.class.getResourceAsStream(RESOURCE)) {
			if (in == null) {
				return "unstamped (run from IDE/classes, not a built extension)";
			}
			Properties props = new Properties();
			props.load(in);
			return "git " + props.getProperty("git", "unknown") + ", built " +
				props.getProperty("built", "unknown");
		}
		catch (Exception e) {
			return "unstamped (" + e.getMessage() + ")";
		}
	}
}
