package ebbex.ghidramcpserver;

import java.util.Map;

import ghidra.program.model.listing.Program;
import io.modelcontextprotocol.spec.McpSchema;

/**
 * A single MCP tool exposed by the server. Implementations receive the
 * currently open program; they never need to null-check it.
 */
public interface McpToolDef {

	String name();

	String description();

	/**
	 * JSON Schema (2020-12) for the tool's input, as a plain map, e.g.
	 * {@code Map.of("type", "object", "properties", Map.of(...), "required", List.of(...))}.
	 */
	Map<String, Object> inputSchema();

	/** True if the tool never mutates the program (sets the MCP readOnlyHint). */
	boolean isReadOnly();

	/**
	 * True if the tool persists the program itself (e.g. an async/long-running tool
	 * that saves when it finishes). When true, the endpoint handler does not auto-save
	 * after the call returns.
	 */
	default boolean managesSave() {
		return false;
	}

	McpSchema.CallToolResult execute(Map<String, Object> args, Program program) throws Exception;
}
