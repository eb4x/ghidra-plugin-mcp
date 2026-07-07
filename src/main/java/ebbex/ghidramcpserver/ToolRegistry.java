package ebbex.ghidramcpserver;

import java.util.ArrayList;
import java.util.List;

import ebbex.ghidramcpserver.tools.AnalyzeTool;
import ebbex.ghidramcpserver.tools.BatchTool;
import ebbex.ghidramcpserver.tools.CallsTool;
import ebbex.ghidramcpserver.tools.ClearTool;
import ebbex.ghidramcpserver.tools.CreateTool;
import ebbex.ghidramcpserver.tools.DecompileTool;
import ebbex.ghidramcpserver.tools.DefineTypesTool;
import ebbex.ghidramcpserver.tools.DisassembleTool;
import ebbex.ghidramcpserver.tools.GetProgramInfoTool;
import ebbex.ghidramcpserver.tools.InspectTool;
import ebbex.ghidramcpserver.tools.ListTool;
import ebbex.ghidramcpserver.tools.ManageTypesTool;
import ebbex.ghidramcpserver.tools.ReadBytesTool;
import ebbex.ghidramcpserver.tools.ReadFileTool;
import ebbex.ghidramcpserver.tools.RenameTool;
import ebbex.ghidramcpserver.tools.SearchMemoryTool;
import ebbex.ghidramcpserver.tools.SetCommentTool;
import ebbex.ghidramcpserver.tools.SetDataTypeTool;
import ebbex.ghidramcpserver.tools.SetFunctionSignatureTool;
import ebbex.ghidramcpserver.tools.SyscallsTool;
import ebbex.ghidramcpserver.tools.XrefsTool;
import ebbex.ghidramcpserver.tools.FidApplyTool;
import ebbex.ghidramcpserver.tools.app.FidBuildTool;
import ebbex.ghidramcpserver.tools.app.GetApplicationInfoTool;
import ebbex.ghidramcpserver.tools.app.ImportTool;
import ebbex.ghidramcpserver.tools.app.ListFilesTool;
import ebbex.ghidramcpserver.tools.app.ManageFilesTool;
import ebbex.ghidramcpserver.tools.app.ReadLogTool;
import ebbex.ghidramcpserver.util.Decompilers;
import ebbex.ghidramcpserver.util.ProjectContext;

/** The fixed set of tools, split into the application-level and program groups. */
public final class ToolRegistry {

	private ToolRegistry() {
	}

	/** Application-level tools (project management, import). */
	public static List<ApplicationLevelTool> appTools(ProjectContext context) {
		return List.of(
			new GetApplicationInfoTool(),
			new ReadLogTool(),
			new ListFilesTool(),
			new ManageFilesTool(context),
			new ImportTool(),
			new FidBuildTool());
	}

	/** Program tools (inspect and edit a single program, addressed by project path). */
	public static List<ProgramTool> programTools(Decompilers decompilers) {
		// The single-edit tools batch dispatches to; batch reuses these instances.
		List<ProgramTool> editTools = List.of(
			new RenameTool(decompilers),
			new SetCommentTool(),
			new SetDataTypeTool(decompilers),
			new SetFunctionSignatureTool(decompilers),
			new CreateTool());

		List<ProgramTool> tools = new ArrayList<>();
		// lifecycle
		tools.add(new AnalyzeTool());
		// read
		tools.add(new GetProgramInfoTool());
		tools.add(new ListTool());
		tools.add(new InspectTool());
		tools.add(new DecompileTool(decompilers));
		tools.add(new DisassembleTool());
		tools.add(new ReadBytesTool());
		tools.add(new ReadFileTool());
		tools.add(new XrefsTool());
		tools.add(new CallsTool());
		tools.add(new SyscallsTool());
		tools.add(new SearchMemoryTool());
		tools.add(new ClearTool());
		// write
		tools.addAll(editTools);
		tools.add(new DefineTypesTool());
		tools.add(new ManageTypesTool());
		tools.add(new BatchTool(editTools));
		tools.add(new FidApplyTool());
		return List.copyOf(tools);
	}
}
