package ebbex.ghidramcpserver;

import java.util.Map;

import org.junit.After;
import org.junit.Before;

import generic.test.AbstractGenericTest;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.listing.Program;
import io.modelcontextprotocol.spec.McpSchema;

/**
 * A tool test on an in-memory 16-bit real-mode program, the shape most of this server's
 * sharp edges come from: 2-byte near pointers against 4-byte far ones, {@code seg:off}
 * addresses, overlay-style block names. Tools are called the way the smoke script calls
 * them, {@code execute(args, program)}, with no HTTP layer in between.
 */
public abstract class RealModeProgramTest extends AbstractGenericTest {

	protected ProgramBuilder builder;
	protected Program program;

	@Before
	public void buildProgram() throws Exception {
		builder = new ProgramBuilder("mcp-test", ProgramBuilder._X86_16_REAL_MODE);
		builder.createMemory("CODE", "1000:0000", 0x1000);
		program = builder.getProgram();
	}

	@After
	public void disposeProgram() {
		if (builder != null) {
			builder.dispose();
		}
	}

	/** Run a tool and return its text, failing the test if the tool reported an error. */
	protected String ok(ProgramTool tool, Map<String, Object> args) throws Exception {
		McpSchema.CallToolResult result = tool.execute(args, program);
		String text = text(result);
		if (Boolean.TRUE.equals(result.isError())) {
			throw new AssertionError(tool.name() + " returned an error: " + text);
		}
		return text;
	}

	/** Run a tool and return its text, failing the test unless the tool reported an error. */
	protected String error(ProgramTool tool, Map<String, Object> args) throws Exception {
		McpSchema.CallToolResult result = tool.execute(args, program);
		String text = text(result);
		if (!Boolean.TRUE.equals(result.isError())) {
			throw new AssertionError(tool.name() + " did not return an error: " + text);
		}
		return text;
	}

	protected static String text(McpSchema.CallToolResult result) {
		StringBuilder sb = new StringBuilder();
		for (McpSchema.Content content : result.content()) {
			if (content instanceof McpSchema.TextContent t) {
				sb.append(t.text());
			}
		}
		return sb.toString();
	}
}
