package ebbex.ghidramcpserver;

import java.util.Map;

import ghidra.framework.model.Project;
import io.modelcontextprotocol.spec.McpSchema;

/**
 * An application-level MCP tool: it operates on the Ghidra {@link Project}
 * (managing files, importing) rather than on a single open program. Exposed
 * under the {@code /mcp/application-level} endpoint.
 */
public interface ApplicationLevelTool {

	String name();

	String description();

	Map<String, Object> inputSchema();

	/** True if the tool does not modify the project. */
	boolean isReadOnly();

	/**
	 * True if the tool needs an open project to run. When false, the endpoint invokes the tool
	 * even with no project open (and passes {@code null} for the project) — e.g. a log reader
	 * that must work before any project exists.
	 */
	default boolean requiresProject() {
		return true;
	}

	McpSchema.CallToolResult execute(Map<String, Object> args, Project project) throws Exception;
}
