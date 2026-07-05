package ebbex.ghidramcpserver.tools;

import java.util.Map;

import ebbex.ghidramcpserver.ProgramTool;
import ebbex.ghidramcpserver.util.Results;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.util.GhidraProgramUtilities;
import io.modelcontextprotocol.spec.McpSchema;

/** Program metadata snapshot: name, arch, image base, memory layout, counts. */
public class GetProgramInfoTool implements ProgramTool {

	@Override
	public String name() {
		return "get_program_info";
	}

	@Override
	public String description() {
		return "Get metadata about the currently open program: name, executable path, " +
			"architecture/compiler, image base, entry points, memory blocks, and " +
			"function/symbol counts.";
	}

	@Override
	public Map<String, Object> inputSchema() {
		return Map.of("type", "object", "properties", Map.of());
	}

	@Override
	public boolean isReadOnly() {
		return true;
	}

	@Override
	public McpSchema.CallToolResult execute(Map<String, Object> args, Program program) {
		StringBuilder sb = new StringBuilder();
		sb.append("Program: ").append(program.getName()).append('\n');
		sb.append("Executable: ").append(program.getExecutablePath()).append('\n');
		sb.append("Format: ").append(program.getExecutableFormat()).append('\n');
		sb.append("Language: ").append(program.getLanguageID()).append('\n');
		sb.append("Compiler spec: ").append(program.getCompilerSpec().getCompilerSpecID())
				.append('\n');
		sb.append("Image base: ").append(program.getImageBase()).append('\n');

		boolean analyzed = GhidraProgramUtilities.isAnalyzed(program);
		boolean analyzing =
			AutoAnalysisManager.getAnalysisManager(program).isAnalyzing();
		sb.append("Analyzed: ").append(analyzed)
				.append(analyzing ? " (analysis in progress)" : "").append('\n');
		sb.append("Functions: ").append(program.getFunctionManager().getFunctionCount())
				.append('\n');
		sb.append("Symbols: ").append(program.getSymbolTable().getNumSymbols()).append('\n');

		appendFileCoverage(sb, program);

		sb.append("Entry points:");
		var entryPoints = program.getSymbolTable().getExternalEntryPointIterator();
		int entryCount = 0;
		while (entryPoints.hasNext() && entryCount < 10) {
			Address a = entryPoints.next();
			sb.append(' ').append(a);
			entryCount++;
		}
		sb.append('\n');

		Memory memory = program.getMemory();
		sb.append("Memory blocks (").append(memory.getBlocks().length).append("):\n");
		for (MemoryBlock block : memory.getBlocks()) {
			sb.append(String.format("  %-16s %s-%s %s%s%s %s%n", block.getName(),
				block.getStart(), block.getEnd(), block.isRead() ? "r" : "-",
				block.isWrite() ? "w" : "-", block.isExecute() ? "x" : "-",
				block.isInitialized() ? "" : "(uninitialized)"));
		}
		return Results.ok(sb.toString());
	}

	/**
	 * Compare the on-disk file size to the loaded (initialized) footprint. A large
	 * excess means most of the file was never mapped — the classic signature of an
	 * overlay/packed payload or a bound DOS extender stub (loaded image is tiny).
	 */
	private static void appendFileCoverage(StringBuilder sb, Program program) {
		java.io.File file = new java.io.File(program.getExecutablePath());
		if (!file.isFile()) {
			return;
		}
		long onDisk = file.length();
		long loaded = 0;
		for (MemoryBlock block : program.getMemory().getBlocks()) {
			if (block.isInitialized()) {
				loaded += block.getSize();
			}
		}
		sb.append("On disk: ").append(onDisk).append(" bytes; loaded (initialized): ")
				.append(loaded).append(" bytes\n");
		if (onDisk > loaded * 2 && onDisk - loaded > 4096) {
			sb.append("  ! ~").append(onDisk - loaded)
					.append(" bytes on disk are not mapped — likely an overlay / packed payload / " +
						"bound DOS-extender stub. Use read_file to inspect the raw file.\n");
		}
	}
}
