// Headless smoke test for the refactored two-group design. Exercises the
// application-level tools (project info, list, import) and the program tools
// (analyze + inspect/edit by path), verifying writes persist. Not shipped in
// the extension (excluded from buildExtension).
//@category MCP
import java.util.List;
import java.util.Map;

import ebbex.ghidramcpserver.AppLevelTool;
import ebbex.ghidramcpserver.McpToolDef;
import ebbex.ghidramcpserver.ToolRegistry;
import ebbex.ghidramcpserver.util.Decompilers;
import ebbex.ghidramcpserver.util.ProjectContext;
import ghidra.app.script.GhidraScript;
import ghidra.framework.main.AppInfo;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.Project;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import io.modelcontextprotocol.spec.McpSchema;

public class McpToolSmokeScript extends GhidraScript {

	private List<AppLevelTool> appTools;
	private List<McpToolDef> programTools;

	@Override
	protected void run() throws Exception {
		appTools = ToolRegistry.appTools();
		programTools = ToolRegistry.programTools(new Decompilers());

		Project project = state.getProject();
		println("=== project = " + project.getName() +
			"  | AppInfo.getActiveProject() = " + AppInfo.getActiveProject() + " ===");

		// ---- application-level tools ----
		app("get_application_info", Map.of(), project);
		app("import", Map.of("source", "/bin/ls", "folder", "/"), project);
		app("list_files", Map.of(), project);

		// ---- open the imported program by its project path ----
		DomainFile df = project.getProjectData().getFile("/ls");
		if (df == null) {
			println("!! import did not create /ls");
			return;
		}
		Program program = (Program) df.getDomainObject(this, false, false, TaskMonitor.DUMMY);
		try {
			// ---- program tools ----
			prog("analyze", Map.of(), program);
			prog("get_program_info", Map.of(), program);
			prog("list", Map.of("kind", "functions", "filter", "main", "limit", 3), program);
			prog("decompile", Map.of("function", "_init"), program);
			prog("rename", Map.of("target", "function", "function", "_init",
				"new_name", "mcp_renamed_init"), program);
			df.save(TaskMonitor.DUMMY);
			prog("list", Map.of("kind", "functions", "filter", "mcp_renamed_init"), program);
		}
		finally {
			program.release(this);
		}

		// ---- reopen to confirm the rename persisted ----
		Program reopened = (Program) df.getDomainObject(this, false, false, TaskMonitor.DUMMY);
		try {
			boolean found = false;
			for (var f : reopened.getFunctionManager().getFunctions(true)) {
				if (f.getName().equals("mcp_renamed_init")) {
					found = true;
					break;
				}
			}
			println("=== rename persisted after reopen: " + found + " ===");
		}
		finally {
			reopened.release(this);
		}
	}

	private void app(String name, Map<String, Object> args, Project project) throws Exception {
		AppLevelTool tool =
			appTools.stream().filter(t -> t.name().equals(name)).findFirst().orElseThrow();
		println("\n----- app:" + name + " " + args + " -----");
		print(tool.execute(args, project));
	}

	private void prog(String name, Map<String, Object> args, Program program) throws Exception {
		McpToolDef tool =
			programTools.stream().filter(t -> t.name().equals(name)).findFirst().orElseThrow();
		println("\n----- program:" + name + " " + args + " -----");
		print(tool.execute(args, program));
	}

	private void print(McpSchema.CallToolResult result) {
		for (McpSchema.Content c : result.content()) {
			if (c instanceof McpSchema.TextContent t) {
				println(t.text());
			}
		}
		if (Boolean.TRUE.equals(result.isError())) {
			println("[isError=true]");
		}
	}
}
