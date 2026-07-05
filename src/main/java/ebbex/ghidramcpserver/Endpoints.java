package ebbex.ghidramcpserver;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import ebbex.ghidramcpserver.util.Args;
import ebbex.ghidramcpserver.util.ProjectContext;
import ebbex.ghidramcpserver.util.Results;
import ebbex.ghidramcpserver.util.Schemas;
import ghidra.framework.model.Project;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import io.modelcontextprotocol.server.McpServerFeatures;
import io.modelcontextprotocol.spec.McpSchema;

/**
 * Builds the MCP endpoints (tool groups) and their per-tool call handlers.
 *
 * <ul>
 * <li>{@code application-level} &mdash; {@link ApplicationLevelTool}s bound to the active project.</li>
 * <li>{@code program} &mdash; {@link ProgramTool}s; every tool's schema is augmented with a
 * required {@code program} project-path argument, resolved on demand and saved after writes.</li>
 * </ul>
 */
public final class Endpoints {

	private Endpoints() {
	}

	public static List<McpHttpServer.Endpoint> build(ProjectContext context,
			List<ApplicationLevelTool> appTools, List<ProgramTool> programTools) {
		return List.of(
			new McpHttpServer.Endpoint("application-level", "ghidra-application-level",
				appTools.stream().map(t -> appSpec(context, t)).toList()),
			new McpHttpServer.Endpoint("program", "ghidra-program",
				programTools.stream().map(t -> programSpec(context, t)).toList()));
	}

	// ---- application-level group ----

	private static McpServerFeatures.SyncToolSpecification appSpec(ProjectContext context,
			ApplicationLevelTool tool) {
		McpSchema.Tool mcpTool = McpSchema.Tool.builder(tool.name(), tool.inputSchema())
				.description(tool.description())
				.annotations(McpSchema.ToolAnnotations.builder()
						.readOnlyHint(tool.isReadOnly())
						.build())
				.build();

		return McpServerFeatures.SyncToolSpecification.builder()
				.tool(mcpTool)
				.callHandler((exchange, request) -> {
					Project project = context.project();
					if (project == null) {
						return Results.error("No project is open in Ghidra");
					}
					Map<String, Object> args = arguments(request);
					try {
						return tool.execute(args, project);
					}
					catch (Exception e) {
						Msg.error(Endpoints.class, "app tool " + tool.name() + " failed", e);
						return Results.error(tool.name() + " failed: " + e);
					}
				})
				.build();
	}

	// ---- program group ----

	private static McpServerFeatures.SyncToolSpecification programSpec(ProjectContext context,
			ProgramTool tool) {
		McpSchema.Tool mcpTool = McpSchema.Tool.builder(tool.name(), augmentWithProgram(tool))
				.description(tool.description() +
					" The 'program' argument is a project file path, e.g. /malware.exe.")
				.annotations(McpSchema.ToolAnnotations.builder()
						.readOnlyHint(tool.isReadOnly())
						.build())
				.build();

		return McpServerFeatures.SyncToolSpecification.builder()
				.tool(mcpTool)
				.callHandler((exchange, request) -> {
					if (context.project() == null) {
						return Results.error("No project is open in Ghidra");
					}
					Map<String, Object> args = arguments(request);
					String path = Args.stringArg(args, "program", null);
					if (path == null || path.isBlank()) {
						return Results.error("'program' (a project file path) is required");
					}
					Program program;
					try {
						program = context.openProgram(path);
					}
					catch (Exception e) {
						return Results.error("Could not open program '" + path + "': " +
							e.getMessage());
					}
					// Reads run lock-free; writes serialize per program so a concurrent
					// save() can't corrupt the file.
					if (tool.isReadOnly()) {
						return runTool(tool, args, program);
					}
					var lock = context.writeLock(path);
					lock.lock();
					try {
						McpSchema.CallToolResult result = runTool(tool, args, program);
						if (!tool.managesSave() && !Boolean.TRUE.equals(result.isError())) {
							try {
								context.save(path);
							}
							catch (Exception e) {
								return Results.error("Edit applied but saving '" + path +
									"' failed: " + e.getMessage());
							}
						}
						return result;
					}
					finally {
						lock.unlock();
					}
				})
				.build();
	}

	private static McpSchema.CallToolResult runTool(ProgramTool tool, Map<String, Object> args,
			Program program) {
		try {
			return tool.execute(args, program);
		}
		catch (Exception e) {
			Msg.error(Endpoints.class, "program tool " + tool.name() + " failed", e);
			return Results.error(tool.name() + " failed: " + e);
		}
	}

	/** Return a copy of the tool's schema with a required {@code program} string added. */
	private static Map<String, Object> augmentWithProgram(ProgramTool tool) {
		Map<String, Object> schema = new LinkedHashMap<>(tool.inputSchema());

		Object propsObj = schema.get("properties");
		Map<String, Object> properties = new LinkedHashMap<>();
		if (propsObj instanceof Map<?, ?> existing) {
			existing.forEach((k, v) -> properties.put(String.valueOf(k), v));
		}
		properties.put("program", Schemas.stringProp("Project file path of the target program"));
		schema.put("properties", properties);

		List<Object> required = new ArrayList<>();
		Object reqObj = schema.get("required");
		if (reqObj instanceof List<?> existing) {
			required.addAll(existing);
		}
		if (!required.contains("program")) {
			required.add("program");
		}
		schema.put("required", required);

		schema.putIfAbsent("type", "object");
		return schema;
	}

	private static Map<String, Object> arguments(McpSchema.CallToolRequest request) {
		return request.arguments() != null ? request.arguments() : Map.of();
	}
}
