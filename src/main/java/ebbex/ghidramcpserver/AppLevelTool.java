package ebbex.ghidramcpserver;

import java.util.Map;

import ghidra.framework.model.Project;
import io.modelcontextprotocol.spec.McpSchema;

/**
 * An application-level MCP tool: it operates on the Ghidra {@link Project}
 * (managing files, importing) rather than on a single open program. Exposed
 * under the {@code /mcp/application-level} endpoint.
 */
public interface AppLevelTool {

	String name();

	String description();

	Map<String, Object> inputSchema();

	/** True if the tool does not modify the project. */
	boolean isReadOnly();

	McpSchema.CallToolResult execute(Map<String, Object> args, Project project) throws Exception;
}
