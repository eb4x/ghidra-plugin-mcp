package ebbex.ghidramcpserver.tools.app;

import java.io.File;
import java.io.IOException;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.PathMatcher;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import ebbex.ghidramcpserver.ApplicationLevelTool;
import ebbex.ghidramcpserver.util.Analysis;
import ebbex.ghidramcpserver.util.Args;
import ebbex.ghidramcpserver.util.ProjectContext;
import ebbex.ghidramcpserver.util.Results;
import ebbex.ghidramcpserver.util.Schemas;
import ghidra.app.util.importer.ProgramLoader;
import ghidra.app.util.opinion.LoadException;
import ghidra.app.util.opinion.LoadResults;
import ghidra.app.util.opinion.Loaded;
import ghidra.app.util.opinion.Loader;
import ghidra.formats.gfilesystem.FSRL;
import ghidra.formats.gfilesystem.FileSystemRef;
import ghidra.formats.gfilesystem.FileSystemService;
import ghidra.formats.gfilesystem.GFile;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.Project;
import ghidra.program.model.lang.LanguageNotFoundException;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.classfinder.ClassSearcher;
import ghidra.util.task.TaskMonitor;
import io.modelcontextprotocol.spec.McpSchema;

/**
 * Import files from the host filesystem into the project (Ghidra picks the best
 * loader; for headerless/raw binaries the loader, language and base address can be
 * forced). {@code file} may name one file, a directory, or a glob, and a file that no
 * loader claims but that Ghidra can open as a container filesystem (an OMF {@code .LIB},
 * an {@code ar} archive, a zip) is expanded into one program per member. Analysis is
 * optional ({@code analyze=true} queues it) &mdash; otherwise use the program tool
 * {@code analyze} afterwards.
 */
public class ImportTool implements ApplicationLevelTool {

	/** How many created paths the summary lists before it points at list_files instead. */
	private static final int MAX_LISTED = 200;

	private final ProjectContext context;

	public ImportTool(ProjectContext context) {
		this.context = context;
	}

	@Override
	public String name() {
		return "import";
	}

	@Override
	public String description() {
		return "Import binaries from the host filesystem into the project. 'file' is one file, a " +
			"directory (every file directly inside it), or a glob such as '/lib/objs/*.obj' " +
			"('**' recurses). A file no loader claims is probed as a container (OMF .LIB, ar " +
			"archive, zip): each member becomes a program. Ghidra auto-detects the format. Returns " +
			"the created project file path(s), which you then pass as 'program' to program tools. " +
			"Pass analyze=true to queue auto-analysis of everything imported (poll " +
			"get_program_info), or run 'analyze' yourself. For a headerless/raw binary that " +
			"auto-detect rejects, pass 'loader' plus 'processor' (and usually 'base_address').";
	}

	@Override
	public Map<String, Object> inputSchema() {
		return Map.of(
			"type", "object",
			"properties", Map.of(
				"file", Schemas.stringProp("Absolute host path: a file, a directory, or a glob " +
					"('*', '?', '[..]', '{a,b}', '**' for recursion)"),
				"folder", Schemas.stringProp("Destination project folder (default '/')"),
				"analyze", Schemas.boolProp("Queue auto-analysis of each imported program " +
					"(default false; one program is analyzed at a time, in the background)"),
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

	/** The loader settings shared by every file of one call. */
	private record Settings(Project project, String folder, Class<? extends Loader> loaderClass,
			String loaderName, String processor, String cspec, String baseAddress) {

		ProgramLoader.Builder builder() {
			ProgramLoader.Builder builder = ProgramLoader.builder()
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
			return builder;
		}
	}

	@Override
	public McpSchema.CallToolResult execute(Map<String, Object> args, Project project)
			throws Exception {
		String source = Args.stringArg(args, "file", null);
		if (source == null || source.isBlank()) {
			return Results.error("'file' (a host filesystem path) is required");
		}
		String folder = Args.stringArg(args, "folder", "/");
		boolean analyze = Args.boolArg(args, "analyze", false);
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
		Settings settings =
			new Settings(project, folder, loaderClass, loaderName, processor, cspec, baseAddress);

		List<File> files = expand(source);
		boolean single = !isGlob(source) && !new File(source).isDirectory();
		if (files.isEmpty()) {
			return Results.error(single
					? "Not a file on the host: " + source
					: "No files match " + source);
		}

		List<String> created = new ArrayList<>();
		List<String> failures = new ArrayList<>();
		for (File file : files) {
			importOne(file, settings, created, failures);
		}
		if (single && created.isEmpty() && !failures.isEmpty()) {
			return Results.error(failures.get(0));
		}

		if (created.isEmpty()) {
			return Results.error("No programs were produced from " + source +
				(failures.isEmpty() ? "" : ":\n  " + String.join("\n  ", failures)));
		}

		int queued = 0;
		List<String> analyzeFailures = new ArrayList<>();
		if (analyze) {
			for (String path : created) {
				try {
					Program program = context.openProgram(path);
					if (Analysis.enqueue(program)) {
						queued++;
					}
				}
				catch (Exception e) {
					analyzeFailures.add(path + ": " + e.getMessage());
				}
			}
		}

		StringBuilder sb = new StringBuilder();
		if (single && created.size() == 1) {
			sb.append("Imported ").append(source).append(" ->\n  ").append(created.get(0));
		}
		else {
			sb.append("Imported ").append(created.size()).append(" program(s) from ")
					.append(files.size()).append(" host file(s) matching ").append(source)
					.append(" ->");
			for (int i = 0; i < Math.min(created.size(), MAX_LISTED); i++) {
				sb.append("\n  ").append(created.get(i));
			}
			if (created.size() > MAX_LISTED) {
				sb.append("\n  ... and ").append(created.size() - MAX_LISTED)
						.append(" more (list_files folder=").append(folder).append(')');
			}
		}
		if (!failures.isEmpty()) {
			sb.append("\nFailed (").append(failures.size()).append("):\n  ")
					.append(String.join("\n  ", failures));
		}
		if (analyze) {
			sb.append("\nQueued analysis of ").append(queued).append(" program(s)");
			int pending = Analysis.pending();
			if (pending > queued) {
				sb.append(" behind ").append(pending - queued).append(" already pending");
			}
			sb.append("; poll get_program_info for 'Analyzed'.");
			if (!analyzeFailures.isEmpty()) {
				sb.append("\nCould not queue:\n  ").append(String.join("\n  ", analyzeFailures));
			}
		}
		else {
			sb.append("\nRun analyze(program=<path>) to analyze (or import with analyze=true).");
		}
		return Results.ok(sb.toString());
	}

	/**
	 * Import one host file: directly if a loader claims it; otherwise, if Ghidra can open it
	 * as a container filesystem, every member file in it. Appends created project paths to
	 * {@code created} and one message per failure to {@code failures}.
	 */
	private static void importOne(File file, Settings settings, List<String> created,
			List<String> failures) {
		try {
			load(settings.builder().source(file), created);
		}
		catch (LanguageNotFoundException e) {
			failures.add("Unknown processor '" + settings.processor() + "': " + e.getMessage());
		}
		catch (LoadException e) {
			String msg = e.getMessage() != null ? e.getMessage() : "";
			if (msg.contains("No load spec found")) {
				String probe = importContainer(file, settings, created, failures);
				if (probe == null) {
					return;
				}
				if (settings.processor() == null) {
					failures.add("No loader claims " + file + " and it is not a container Ghidra " +
						"can open (LoadException: No load spec found). If this is a " +
						"headerless/raw binary, pass loader='BinaryLoader' plus processor (a " +
						"language ID such as 'x86:LE:16:Real Mode') and usually base_address." +
						(probe.isEmpty() ? "" : " Container probe: " + probe));
					return;
				}
				failures.add("No load spec found for " + file + " with loader=" +
					settings.loaderName() + ", processor=" + settings.processor() +
					(settings.cspec() != null ? ", cspec=" + settings.cspec() : "") +
					" — check that the language ID exists and that the cspec belongs to it.");
				return;
			}
			if (msg.contains("Cannot load with null options")) {
				failures.add("The loader rejected an option value — check base_address '" +
					settings.baseAddress() + "' (hex like '0x7c00', or segmented '07c0:0000').");
				return;
			}
			failures.add(file + ": " + msg);
		}
		catch (Exception e) {
			Msg.error(ImportTool.class, "import of " + file + " failed", e);
			failures.add(file + ": " + e);
		}
	}

	/**
	 * Expand a container file (OMF .LIB, ar archive, zip…) into one program per member.
	 * Returns null when the file was a container and its members were attempted (each
	 * member failure lands in {@code failures}), "" when it is not a container, or a probe
	 * error message.
	 */
	private static String importContainer(File file, Settings settings, List<String> created,
			List<String> failures) {
		FileSystemService fss = FileSystemService.getInstance();
		FSRL fsrl = fss.getLocalFSRL(file);
		try (FileSystemRef ref = fss.probeFileForFilesystem(fsrl, TaskMonitor.DUMMY, null)) {
			if (ref == null) {
				return "";
			}
			String kind = ref.getFilesystem().getDescription();
			int members = 0;
			for (GFile member : ref.getFilesystem().files(f -> !f.isDirectory())) {
				members++;
				try {
					load(settings.builder().source(member.getFSRL()), created);
				}
				catch (Exception e) {
					failures.add(file.getName() + " member " + member.getName() + ": " +
						e.getMessage());
				}
			}
			if (members == 0) {
				return kind + " with no member files";
			}
			return null;
		}
		catch (Exception e) {
			return "could not open " + file + " as a container: " + e.getMessage();
		}
	}

	private static void load(ProgramLoader.Builder builder, List<String> created)
			throws Exception {
		try (LoadResults<Program> results = builder.load()) {
			for (Loaded<Program> loaded : results) {
				DomainFile domainFile = loaded.save(TaskMonitor.DUMMY);
				created.add(domainFile.getPathname());
			}
		}
	}

	private static boolean isGlob(String path) {
		return path.chars().anyMatch(c -> c == '*' || c == '?' || c == '[' || c == '{');
	}

	/**
	 * A plain file → itself; a directory → its regular files (one level); a glob → every
	 * regular file under the longest glob-free prefix that the whole pattern matches.
	 */
	private static List<File> expand(String source) throws IOException {
		File file = new File(source);
		if (!isGlob(source)) {
			if (file.isFile()) {
				return List.of(file);
			}
			if (file.isDirectory()) {
				File[] children = file.listFiles(File::isFile);
				List<File> out = children == null ? new ArrayList<>() : new ArrayList<>(List.of(children));
				out.sort(null);
				return out;
			}
			return List.of();
		}
		Path pattern = Path.of(source);
		Path base = pattern.getRoot() != null ? pattern.getRoot() : Path.of("");
		for (Path part : pattern) {
			if (isGlob(part.toString())) {
				break;
			}
			base = base.resolve(part);
		}
		if (!Files.isDirectory(base)) {
			return List.of();
		}
		PathMatcher matcher = FileSystems.getDefault().getPathMatcher("glob:" + source);
		int depth = source.contains("**") ? Integer.MAX_VALUE : pattern.getNameCount();
		try (Stream<Path> walk = Files.walk(base, depth)) {
			return walk.filter(Files::isRegularFile)
					.filter(matcher::matches)
					.sorted()
					.map(Path::toFile)
					.collect(Collectors.toList());
		}
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
