package ebbex.ghidramcpserver.tools.app;

import java.io.File;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import ebbex.ghidramcpserver.AppLevelTool;
import ebbex.ghidramcpserver.util.Results;
import ghidra.app.util.importer.ProgramLoader;
import ghidra.app.util.opinion.Loaded;
import ghidra.app.util.opinion.LoadResults;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.Project;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import io.modelcontextprotocol.spec.McpSchema;

/**
 * Import a file from the host filesystem into the project (Ghidra picks the best
 * loader). Does not run analysis &mdash; use the program tool {@code analyze} afterwards.
 */
public class ImportTool implements AppLevelTool {

	@Override
	public String name() {
		return "import";
	}

	@Override
	public String description() {
		return "Import a binary from the host filesystem into the project. Ghidra auto-detects the " +
			"format. Returns the created project file path(s), which you then pass as 'program' to " +
			"program tools (run 'analyze' first to populate functions).";
	}

	@Override
	public Map<String, Object> inputSchema() {
		return Map.of(
			"type", "object",
			"properties", Map.of(
				"source", Results.stringProp("Absolute path to the file on the host filesystem"),
				"folder", Results.stringProp("Destination project folder (default '/')")),
			"required", List.of("source"));
	}

	@Override
	public boolean isReadOnly() {
		return false;
	}

	@Override
	public McpSchema.CallToolResult execute(Map<String, Object> args, Project project)
			throws Exception {
		String source = Results.stringArg(args, "source", null);
		if (source == null || source.isBlank()) {
			return Results.error("source is required");
		}
		File file = new File(source);
		if (!file.isFile()) {
			return Results.error("Not a file on the host: " + source);
		}
		String folder = Results.stringArg(args, "folder", "/");

		List<String> created = new ArrayList<>();
		try (LoadResults<Program> results = ProgramLoader.builder()
				.source(file)
				.project(project)
				.projectFolderPath(folder)
				.load()) {
			for (Loaded<Program> loaded : results) {
				DomainFile domainFile = loaded.save(TaskMonitor.DUMMY);
				created.add(domainFile.getPathname());
			}
		}

		if (created.isEmpty()) {
			return Results.error("No programs were produced from " + source);
		}
		return Results.ok("Imported " + source + " ->\n  " + String.join("\n  ", created) +
			"\nRun analyze(program=<path>) to analyze.");
	}
}
