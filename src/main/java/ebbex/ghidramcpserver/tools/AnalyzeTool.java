package ebbex.ghidramcpserver.tools;

import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import ebbex.ghidramcpserver.ProgramTool;
import ebbex.ghidramcpserver.util.Results;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.program.model.listing.Program;
import ghidra.program.util.GhidraProgramUtilities;
import ghidra.util.Msg;
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
			"Run this once after importing a fresh binary.";
	}

	@Override
	public Map<String, Object> inputSchema() {
		return Map.of("type", "object", "properties", Map.of());
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
}
