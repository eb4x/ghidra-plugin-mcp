package ebbex.ghidramcpserver.tools;

import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

import ebbex.ghidramcpserver.ProgramTool;
import ebbex.ghidramcpserver.util.Args;
import ebbex.ghidramcpserver.util.Results;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.plugin.core.analysis.OneShotAnalysisCommand;
import ghidra.app.services.Analyzer;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.Options;
import ghidra.program.model.listing.Program;
import ghidra.program.util.GhidraProgramUtilities;
import ghidra.util.Msg;
import ghidra.util.classfinder.ClassSearcher;
import ghidra.util.task.TaskMonitor;
import io.modelcontextprotocol.spec.McpSchema;

/**
 * Run Ghidra's auto-analysis on a program. Typically called once after
 * {@code import}, before the other program tools have anything to work with.
 *
 * <p>Analysis of a real binary can take a minute or more &mdash; longer than an MCP
 * client's request timeout &mdash; so it runs on a background thread and this call
 * returns immediately. Poll {@code get_program_info} for progress (the {@code Analyzed}
 * flag flips true and the function count rises). The program is saved when analysis
 * completes, so this tool persists itself ({@link #managesSave()}).
 *
 * <p>Pass the optional {@code analyzer} argument to run a <em>single</em> named analyzer
 * as a one-shot &mdash; the programmatic equivalent of the GUI <em>Analysis &rarr; One
 * Shot</em> menu &mdash; instead of full auto-analysis. This is surgical: it re-runs just
 * that analyzer over an already-analyzed program without disturbing the rest of the
 * markup. The canonical use is re-running the {@code RTLink/Plus Overlay} analyzer to
 * retrofit the assumed data segment (DS/DGROUP) onto a program that was analyzed before
 * that support existed. The one-shot path runs synchronously and returns the analyzer's
 * own log output.
 *
 * <p>Analysis runs inside a single transaction (mirroring the headless analyzer);
 * some analyzers &mdash; notably the RTLink/Plus Overlay analyzer &mdash; require an
 * open transaction and NPE without one.
 */
public class AnalyzeTool implements ProgramTool {

	private final Set<String> analyzing = ConcurrentHashMap.newKeySet();

	@Override
	public String name() {
		return "analyze";
	}

	@Override
	public String description() {
		return "Run auto-analysis on the program (disassemble, recover functions, etc.). Runs in " +
			"the background and returns immediately; poll get_program_info until 'Analyzed' is true. " +
			"Run this once after importing a fresh binary. Optionally pass 'analyzer' to instead run " +
			"just that one named analyzer as a synchronous one-shot (like the GUI Analysis → One " +
			"Shot menu), e.g. \"RTLink/Plus Overlay\" to retrofit the data segment on an " +
			"already-analyzed program.";
	}

	@Override
	public Map<String, Object> inputSchema() {
		return Map.of("type", "object", "properties", Map.of(
			"analyzer", Map.of(
				"type", "string",
				"description", "Optional: run only this single named analyzer as a one-shot " +
					"(exact display name, e.g. \"RTLink/Plus Overlay\") instead of full " +
					"auto-analysis. Runs synchronously and returns the analyzer's log.")));
	}

	@Override
	public boolean isReadOnly() {
		return false;
	}

	@Override
	public boolean managesSave() {
		return true;
	}

	@Override
	public McpSchema.CallToolResult execute(Map<String, Object> args, Program program) {
		String analyzerName = Args.stringArg(args, "analyzer", null);
		if (analyzerName != null && !analyzerName.isBlank()) {
			return runOneShot(program, analyzerName.trim());
		}

		String key = program.getDomainFile().getPathname();
		if (!analyzing.add(key)) {
			return Results.ok("Analysis already running for " + program.getName() +
				"; poll get_program_info.");
		}

		Thread worker = new Thread(() -> runAnalysis(program, key),
			"mcp-analyze-" + program.getName());
		worker.setDaemon(true);
		worker.start();

		return Results.ok("Started analysis of " + program.getName() + " in the background. " +
			"Poll get_program_info: 'Analyzed' becomes true and 'Functions' rises when it finishes.");
	}

	private void runAnalysis(Program program, String key) {
		try {
			AutoAnalysisManager mgr = AutoAnalysisManager.getAnalysisManager(program);
			int txId = program.startTransaction("Auto-analysis");
			try {
				mgr.initializeOptions();
				mgr.reAnalyzeAll(null);
				mgr.startAnalysis(TaskMonitor.DUMMY);
				GhidraProgramUtilities.markProgramAnalyzed(program);
			}
			finally {
				program.endTransaction(txId, true);
			}
			program.getDomainFile().save(TaskMonitor.DUMMY);
			Msg.info(this, "MCP: analysis complete for " + program.getName() + " (" +
				program.getFunctionManager().getFunctionCount() + " functions)");
		}
		catch (Exception e) {
			Msg.error(this, "MCP: analysis failed for " + program.getName(), e);
		}
		finally {
			analyzing.remove(key);
		}
	}

	/**
	 * Run a single named analyzer as a one-shot (GUI <em>Analysis &rarr; One Shot</em>
	 * equivalent): resolve the analyzer configured for this program, apply the saved
	 * options, and invoke it synchronously inside a transaction over all of memory.
	 * Returns the analyzer's own {@link MessageLog} so the caller sees what it did.
	 */
	private McpSchema.CallToolResult runOneShot(Program program, String analyzerName) {
		AutoAnalysisManager mgr = AutoAnalysisManager.getAnalysisManager(program);
		mgr.initializeOptions();
		Analyzer analyzer = mgr.getAnalyzer(analyzerName);
		if (analyzer == null) {
			return Results.error("No analyzer named '" + analyzerName + "' applies to " +
				program.getName() + ". One-shot analyzers available for this program: " +
				availableOneShotAnalyzers(program));
		}

		MessageLog log = new MessageLog();
		boolean applied;
		int txId = program.startTransaction("One-shot analysis: " + analyzerName);
		try {
			Options options = program.getOptions(Program.ANALYSIS_PROPERTIES);
			analyzer.optionsChanged(options.getOptions(analyzer.getName()), program);
			OneShotAnalysisCommand cmd =
				new OneShotAnalysisCommand(analyzer, program.getMemory(), log);
			applied = cmd.applyTo(program, TaskMonitor.DUMMY);
		}
		finally {
			program.endTransaction(txId, true);
		}

		try {
			program.getDomainFile().save(TaskMonitor.DUMMY);
		}
		catch (Exception e) {
			Msg.error(this, "MCP: save failed after one-shot " + analyzerName, e);
		}

		Msg.info(this, "MCP: one-shot analyzer '" + analyzerName + "' on " + program.getName() +
			" returned " + applied);

		StringBuilder sb = new StringBuilder();
		sb.append(applied ? "Ran" : "Attempted (analyzer returned false)")
				.append(" one-shot analyzer '").append(analyzerName).append("' on ")
				.append(program.getName()).append('.');
		String detail = log.toString().strip();
		if (!detail.isEmpty()) {
			sb.append('\n').append(detail);
		}
		return Results.ok(sb.toString());
	}

	/** Comma-separated names of analyzers that offer one-shot analysis for this program. */
	private static String availableOneShotAnalyzers(Program program) {
		return ClassSearcher.getInstances(Analyzer.class).stream()
				.filter(a -> a.supportsOneTimeAnalysis() && a.canAnalyze(program))
				.map(Analyzer::getName)
				.distinct()
				.sorted()
				.collect(Collectors.joining(", "));
	}
}
