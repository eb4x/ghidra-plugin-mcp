package ebbex.ghidramcpserver;

import java.util.List;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import ebbex.ghidramcpserver.util.Decompilers;
import ebbex.ghidramcpserver.util.ProjectContext;
import ghidra.MiscellaneousPluginPackage;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.framework.main.ApplicationLevelPlugin;
import ghidra.framework.model.Project;
import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.util.Msg;

/**
 * Application-level Ghidra plugin that embeds an MCP server. Because it is an
 * {@link ApplicationLevelPlugin} with {@link PluginStatus#RELEASED} status, it is
 * auto-installed into the Front End (project) tool and starts as soon as Ghidra
 * opens &mdash; before any program &mdash; so it can manage projects and import files.
 *
 * <p>The server exposes two MCP endpoints on one port:
 * {@code /mcp/application-level} (project/import) and {@code /mcp/program} (inspect
 * and edit a program addressed by its project path).
 */
//@formatter:off
@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = MiscellaneousPluginPackage.NAME,
	category = PluginCategoryNames.COMMON,
	shortDescription = "MCP server",
	description = "Embeds an MCP (Model Context Protocol) server so that MCP clients "
		+ "(e.g. AI coding agents) can manage the Ghidra project, import files, and inspect/edit "
		+ "programs. Listens on 127.0.0.1:8765 (override with -Dmcp.server.port); endpoints "
		+ "/mcp/application-level and /mcp/program."
)
//@formatter:on
public class MCPServerPlugin extends Plugin implements ApplicationLevelPlugin {

	private static final String HOST = "127.0.0.1";
	private static final int DEFAULT_PORT = 8765;
	private static final String PORT_PROPERTY = "mcp.server.port";
	private static final String MENU_TITLE = "MCPServer";

	private final Decompilers decompilers = new Decompilers();
	private final ProjectContext projectContext = new ProjectContext(decompilers);
	private final List<McpHttpServer.Endpoint> endpoints = Endpoints.build(projectContext,
		ToolRegistry.appTools(projectContext), ToolRegistry.programTools(decompilers));
	private final int port = Integer.getInteger(PORT_PROPERTY, DEFAULT_PORT);

	private McpHttpServer server;

	public MCPServerPlugin(PluginTool tool) {
		super(tool);
	}

	@Override
	protected void init() {
		super.init();
		startServer();
		createMenuActions();
	}

	private synchronized boolean startServer() {
		if (server != null && server.isRunning()) {
			return true;
		}
		McpHttpServer candidate = new McpHttpServer(HOST, port, endpoints);
		try {
			candidate.start();
			server = candidate;
			return true;
		}
		catch (Exception e) {
			server = null;
			Msg.warn(this, "MCP server not started on " + HOST + ":" + port + " (" +
				e.getMessage() + "). Use Tools → " + MENU_TITLE + " → Restart Server " +
				"after freeing the port (or set -D" + PORT_PROPERTY + "=<port>).");
			return false;
		}
	}

	private synchronized void stopServer() {
		if (server != null) {
			server.stop();
			server = null;
		}
	}

	private synchronized boolean isRunning() {
		return server != null && server.isRunning();
	}

	private void createMenuActions() {
		DockingAction statusAction = new DockingAction("MCP Server Status", getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				Project project = projectContext.project();
				StringBuilder sb = new StringBuilder(MENU_TITLE + "\n\n");
				sb.append("Base:    http://").append(HOST).append(':').append(port)
						.append(McpHttpServer.BASE_PATH).append('\n');
				sb.append("State:   ").append(isRunning() ? "Running" : "Stopped").append('\n');
				sb.append("Project: ").append(project != null ? project.getName() : "(none open)")
						.append("\n\nEndpoints:");
				for (McpHttpServer.Endpoint endpoint : endpoints) {
					sb.append("\n  ").append(endpoint.mcpEndpoint()).append("  (")
							.append(endpoint.specs().size()).append(" tools)");
				}
				Msg.showInfo(getClass(), null, MENU_TITLE, sb.toString());
			}
		};
		statusAction.setMenuBarData(
			new MenuData(new String[] { "Tools", MENU_TITLE, "Server Status" }));
		statusAction.setDescription("Show the embedded MCP server's endpoints and state");

		DockingAction restartAction = new DockingAction("MCP Restart Server", getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				stopServer();
				boolean ok = startServer();
				Msg.showInfo(getClass(), null, MENU_TITLE, ok
						? "Server restarted on http://" + HOST + ":" + port + McpHttpServer.BASE_PATH
						: "Server failed to start on " + HOST + ":" + port +
							" (is the port already in use?).");
			}
		};
		restartAction.setMenuBarData(
			new MenuData(new String[] { "Tools", MENU_TITLE, "Restart Server" }));
		restartAction.setDescription("Stop and restart the embedded MCP server");

		tool.addAction(statusAction);
		tool.addAction(restartAction);
	}

	@Override
	protected void dispose() {
		stopServer();
		projectContext.releaseAll();
		decompilers.dispose();
		super.dispose();
	}
}
