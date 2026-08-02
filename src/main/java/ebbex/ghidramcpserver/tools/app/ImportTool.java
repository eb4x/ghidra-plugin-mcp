package ebbex.ghidramcpserver.tools.app;

import java.io.File;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import ebbex.ghidramcpserver.ApplicationLevelTool;
import ebbex.ghidramcpserver.util.Args;
import ebbex.ghidramcpserver.util.Results;
import ebbex.ghidramcpserver.util.Schemas;
import ghidra.app.util.importer.ProgramLoader;
import ghidra.app.util.opinion.LoadException;
import ghidra.app.util.opinion.LoadResults;
import ghidra.app.util.opinion.Loaded;
import ghidra.app.util.opinion.Loader;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.Project;
import ghidra.program.model.lang.LanguageNotFoundException;
import ghidra.program.model.listing.Program;
import ghidra.util.classfinder.ClassSearcher;
import ghidra.util.task.TaskMonitor;
import io.modelcontextprotocol.spec.McpSchema;

/**
 * Import a file from the host filesystem into the project (Ghidra picks the best
 * loader; for headerless/raw binaries the loader, language and base address can be
 * forced). Does not run analysis &mdash; use the program tool {@code analyze} afterwards.
 */
public class ImportTool implements ApplicationLevelTool {

	@Override
	public String name() {
		return "import";
	}

	@Override
	public String description() {
		return "Import a binary from the host filesystem into the project. Ghidra auto-detects the " +
			"format. Returns the created project file path(s), which you then pass as 'program' to " +
			"program tools (run 'analyze' first to populate functions). For a headerless/raw binary " +
			"that auto-detect rejects, pass 'loader' plus 'processor' (and usually 'base_address').";
	}

	@Override
	public Map<String, Object> inputSchema() {
		return Map.of(
			"type", "object",
			"properties", Map.of(
				"file", Schemas.stringProp("Absolute path to the file on the host filesystem"),
				"folder", Schemas.stringProp("Destination project folder (default '/')"),
				"loader", Schemas.stringProp("Loader to force when auto-detect finds none (for " +
					"headerless/raw binaries). Class name like 'BinaryLoader' or display name like " +
					"'Raw Binary'"),
				"processor", Schemas.stringProp("Language ID to load with, e.g. " +
					"'x86:LE:16:Real Mode' (required by loaders like BinaryLoader that cannot " +
					"guess one)"),
				"cspec", Schemas.stringProp("Compiler spec ID, e.g. 'default' or 'gcc' (default: " +
					"the language's default; requires 'processor')"),
				"base_address", Schemas.stringProp("Load address for the image, e.g. '0x7c00' or " +
					"segmented '07c0:0000' (default 0; requires 'processor')")),
			"required", List.of("file"));
	}

	@Override
	public boolean isReadOnly() {
		return false;
	}

	@Override
	public McpSchema.CallToolResult execute(Map<String, Object> args, Project project)
			throws Exception {
		String source = Args.stringArg(args, "file", null);
		if (source == null || source.isBlank()) {
			return Results.error("'file' (a host filesystem path) is required");
		}
		File file = new File(source);
		if (!file.isFile()) {
			return Results.error("Not a file on the host: " + source);
		}
		String folder = Args.stringArg(args, "folder", "/");
		String loaderName = Args.stringArg(args, "loader", null);
		String processor = Args.stringArg(args, "processor", null);
		String cspec = Args.stringArg(args, "cspec", null);
		String baseAddress = Args.stringArg(args, "base_address", null);

		if (cspec != null && processor == null) {
			return Results.error(
				"'cspec' requires 'processor' — a compiler spec means nothing without a language");
		}
		if (baseAddress != null && processor == null) {
			return Results.error(
				"'base_address' requires 'processor' — an address cannot be parsed without a language");
		}
		Class<? extends Loader> loaderClass = null;
		if (loaderName != null) {
			loaderClass = findLoader(loaderName);
			if (loaderClass == null) {
				return Results.error(
					"Unknown loader '" + loaderName + "'. Valid loaders: " + allLoaderNames());
			}
		}

		ProgramLoader.Builder builder = ProgramLoader.builder()
			.source(file)
			.project(project)
			.projectFolderPath(folder);
		if (loaderClass != null) {
			builder.loaders(loaderClass);
		}
		if (processor != null) {
			builder.language(processor);
		}
		if (cspec != null) {
			builder.compiler(cspec);
		}
		if (baseAddress != null) {
			builder.addLoaderArg("-loader-baseAddr", baseAddress);
		}

		List<String> created = new ArrayList<>();
		try (LoadResults<Program> results = builder.load()) {
			for (Loaded<Program> loaded : results) {
				DomainFile domainFile = loaded.save(TaskMonitor.DUMMY);
				created.add(domainFile.getPathname());
			}
		}
		catch (LanguageNotFoundException e) {
			return Results.error("Unknown processor '" + processor + "': " + e.getMessage());
		}
		catch (LoadException e) {
			String msg = e.getMessage() != null ? e.getMessage() : "";
			if (msg.contains("No load spec found")) {
				if (processor == null) {
					return Results.error("No loader claims " + source +
						" (LoadException: No load spec found). If this is a headerless/raw " +
						"binary, pass loader='BinaryLoader' plus processor (a language ID such " +
						"as 'x86:LE:16:Real Mode') and usually base_address.");
				}
				return Results.error("No load spec found for " + source + " with loader=" +
					loaderName + ", processor=" + processor +
					(cspec != null ? ", cspec=" + cspec : "") +
					" — check that the language ID exists and that the cspec belongs to it.");
			}
			if (msg.contains("Cannot load with null options")) {
				return Results.error("The loader rejected an option value — check base_address '" +
					baseAddress + "' (hex like '0x7c00', or segmented '07c0:0000').");
			}
			throw e;
		}

		if (created.isEmpty()) {
			return Results.error("No programs were produced from " + source);
		}
		return Results.ok("Imported " + source + " ->\n  " + String.join("\n  ", created) +
			"\nRun analyze(program=<path>) to analyze.");
	}

	private static Class<? extends Loader> findLoader(String name) {
		return ClassSearcher.getInstances(Loader.class)
			.stream()
			.filter(l -> l.getClass().getSimpleName().equals(name) ||
				l.getName().equalsIgnoreCase(name))
			.findFirst()
			.<Class<? extends Loader>> map(l -> l.getClass())
			.orElse(null);
	}

	private static String allLoaderNames() {
		return ClassSearcher.getInstances(Loader.class)
			.stream()
			.map(l -> l.getName() + " (" + l.getClass().getSimpleName() + ")")
			.distinct()
			.sorted()
			.collect(Collectors.joining(", "));
	}
}
