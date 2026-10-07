package ebbex.ghidramcpserver.tools;

import static org.junit.Assert.assertTrue;

import java.util.Map;

import org.junit.Test;

import ebbex.ghidramcpserver.RealModeProgramTest;

/**
 * kind=instruction matches raw operand text by default (addresses as numbers) and the listing's
 * marked-up text (labels substituted) with markup=true; a pattern written in one form does not
 * match the other, and the no-match note says which form was searched.
 */
public class SearchMemoryMarkupTest extends RealModeProgramTest {

	private final SearchMemoryTool search = new SearchMemoryTool();

	private void jumpToLabeledTarget() throws Exception {
		builder.setBytes("1000:0600", "e9 fd 00", true); // JMP 1000:0700
		builder.createLabel("1000:0700", "target");
	}

	@Test
	public void markupMatchesTheLabelTheListingPrints() throws Exception {
		jumpToLabeledTarget();
		String out = ok(search, Map.of("kind", "instruction", "pattern", "JMP target",
			"markup", true));
		assertTrue(out, out.contains("1000:0600  JMP target"));
	}

	@Test
	public void rawTextDoesNotKnowTheLabelAndSaysSo() throws Exception {
		jumpToLabeledTarget();
		String out = ok(search, Map.of("kind", "instruction", "pattern", "JMP target"));
		assertTrue(out, out.contains("No instructions matching"));
		assertTrue(out, out.contains("needs markup=true"));
		String raw = ok(search, Map.of("kind", "instruction", "pattern", "JMP 0x"));
		assertTrue(raw, raw.contains("1000:0600  JMP 0x"));
	}
}
