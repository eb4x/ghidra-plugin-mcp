package ebbex.ghidramcpserver.tools;

import java.util.Map;

import ebbex.ghidramcpserver.McpToolDef;
import ebbex.ghidramcpserver.util.Results;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.util.GhidraProgramUtilities;
import io.modelcontextprotocol.spec.McpSchema;

/** Program metadata snapshot: name, arch, image base, memory layout, counts. */
public class GetProgramInfoTool implements McpToolDef {

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
		sb.append("Analyzed: ").append(GhidraProgramUtilities.isAnalyzed(program)).append('\n');
		sb.append("Functions: ").append(program.getFunctionManager().getFunctionCount())
				.append('\n');
		sb.append("Symbols: ").append(program.getSymbolTable().getNumSymbols()).append('\n');

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
}
