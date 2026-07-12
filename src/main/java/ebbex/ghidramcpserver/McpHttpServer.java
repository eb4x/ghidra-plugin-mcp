package ebbex.ghidramcpserver;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import org.eclipse.jetty.ee11.servlet.ServletContextHandler;
import org.eclipse.jetty.ee11.servlet.ServletHolder;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.ServerConnector;

import ebbex.ghidramcpserver.util.BuildInfo;
import ghidra.util.Msg;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import io.modelcontextprotocol.json.jackson3.JacksonMcpJsonMapper;
import io.modelcontextprotocol.server.McpServer;
import io.modelcontextprotocol.server.McpServerFeatures;
import io.modelcontextprotocol.server.McpSyncServer;
import io.modelcontextprotocol.server.transport.HttpServletStreamableServerTransportProvider;
import io.modelcontextprotocol.spec.McpSchema;
import tools.jackson.databind.json.JsonMapper;

/**
 * Embedded Jetty server hosting one MCP streamable-HTTP endpoint per tool group,
 * all on a single port. Each {@link Endpoint} is mounted at {@code /mcp/<path>}
 * (e.g. {@code /mcp/application-level}, {@code /mcp/program}) as an independent
 * MCP server, so clients enable only the group(s) they need.
 */
public class McpHttpServer {

	public static final String BASE_PATH = "/mcp";
	public static final String VERSION_PATH = "/version";

	/** One named MCP endpoint: a path segment plus its tool specifications. */
	public record Endpoint(String path, String serverInfoName,
			List<McpServerFeatures.SyncToolSpecification> specs) {

		public String mcpEndpoint() {
			return BASE_PATH + "/" + path;
		}
	}

	private final String host;
	private final int port;
	private final List<Endpoint> endpoints;

	private Server jetty;
	private final List<McpSyncServer> mcpServers = new ArrayList<>();

	public McpHttpServer(String host, int port, List<Endpoint> endpoints) {
		this.host = host;
		this.port = port;
		this.endpoints = endpoints;
	}

	public void start() throws Exception {
		quietVerboseLoggers();
		var jsonMapper = new JacksonMcpJsonMapper(JsonMapper.builder().build());

		jetty = new Server();
		ServerConnector connector = new ServerConnector(jetty);
		connector.setHost(host);
		connector.setPort(port);
		jetty.addConnector(connector);

		ServletContextHandler context = new ServletContextHandler("/");

		for (Endpoint endpoint : endpoints) {
			var transport = HttpServletStreamableServerTransportProvider.builder()
					.jsonMapper(jsonMapper)
					.mcpEndpoint(endpoint.mcpEndpoint())
					.build();

			McpSyncServer mcpServer = McpServer.sync(transport)
					.serverInfo(endpoint.serverInfoName(), BuildInfo.version())
					.capabilities(McpSchema.ServerCapabilities.builder().tools(true).build())
					.tools(endpoint.specs())
					.immediateExecution(true)
					.build();
			mcpServers.add(mcpServer);

			ServletHolder holder = new ServletHolder("mcp-" + endpoint.path(), transport);
			holder.setAsyncSupported(true);
			context.addServlet(holder, endpoint.mcpEndpoint() + "/*");
			context.addServlet(holder, endpoint.mcpEndpoint());
		}

		// Plain-HTTP identity/readiness probe: `curl http://host:port/version` answers both
		// "is the server up?" and "is it my build?" without an MCP session handshake.
		context.addServlet(new ServletHolder("version", new VersionServlet()), VERSION_PATH);

		jetty.setHandler(context);
		jetty.start();

		StringBuilder sb = new StringBuilder("MCP server listening on http://" + host + ":" + port +
			" (build: " + BuildInfo.describe() + ") with " + endpoints.size() + " endpoint(s):");
		for (Endpoint endpoint : endpoints) {
			sb.append("\n  ").append(endpoint.mcpEndpoint()).append("  (")
					.append(endpoint.specs().size()).append(" tools)");
		}
		sb.append("\n  ").append(VERSION_PATH).append("  (plain-HTTP build/readiness probe)");
		Msg.info(this, sb.toString());
	}

	private static class VersionServlet extends HttpServlet {
		@Override
		protected void doGet(HttpServletRequest request, HttpServletResponse response)
				throws IOException {
			response.setContentType("text/plain;charset=utf-8");
			response.getWriter().println("MCPServer " + BuildInfo.describe());
		}
	}

	public boolean isRunning() {
		return jetty != null && jetty.isRunning();
	}

	/**
	 * Jetty and Reactor log through SLF4J, which our bundled log4j bridge routes into
	 * Ghidra's Log4j2. Under Ghidra's development DEBUG config that floods the log, so
	 * pin those libraries' loggers to WARN. (log4j-core is provided by Ghidra.)
	 */
	private static void quietVerboseLoggers() {
		try {
			org.apache.logging.log4j.Level warn = org.apache.logging.log4j.Level.WARN;
			org.apache.logging.log4j.core.config.Configurator.setLevel("org.eclipse.jetty", warn);
			org.apache.logging.log4j.core.config.Configurator.setLevel("reactor", warn);
			// The MCP SDK itself is chatty at DEBUG and routes through the same bridge.
			org.apache.logging.log4j.core.config.Configurator.setLevel("io.modelcontextprotocol",
				warn);
		}
		catch (Throwable t) {
			// logging is best-effort; never let it stop the server
		}
	}

	public void stop() {
		for (McpSyncServer mcpServer : mcpServers) {
			try {
				mcpServer.close();
			}
			catch (Exception e) {
				Msg.warn(this, "Error closing MCP server: " + e.getMessage());
			}
		}
		mcpServers.clear();
		if (jetty != null) {
			try {
				jetty.stop();
			}
			catch (Exception e) {
				Msg.warn(this, "Error stopping Jetty: " + e.getMessage());
			}
			jetty = null;
		}
	}
}
