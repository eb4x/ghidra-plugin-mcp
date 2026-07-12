package ebbex.ghidramcpserver.tools;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import ebbex.ghidramcpserver.ProgramTool;
import ebbex.ghidramcpserver.util.Args;
import ebbex.ghidramcpserver.util.ProjectContext;
import ebbex.ghidramcpserver.util.Results;
import ebbex.ghidramcpserver.util.Schemas;
import ghidra.program.model.listing.Program;
import io.modelcontextprotocol.spec.McpSchema;

/**
 * Persistence and the undo stack: save, undo, redo, history.
 *
 * <p>Every mutating tool call runs inside exactly one named Ghidra transaction (see
 * {@code Transactions.modify}), so the undo stack is a precise record of tool calls — {@code undo}
 * reverts one whole call, whatever its size. That matters most for the bulk tools: a {@code migrate}
 * writing ten thousand items is one transaction, and one {@code op=undo} takes all of it back.
 *
 * <p><b>Undo is not a substitute for care, because it is perishable.</b> The stack lives in memory
 * and does not survive a Ghidra restart, while edits are auto-saved to disk after every call — so a
 * bad write is already persisted, and the only thing that can still take it back dies with the
 * process. An agent that notices its own mistake and reflexively restarts Ghidra to deploy a fix
 * destroys its own way back. Undo first, restart second. (This tool exists because a bulk
 * {@code migrate} once overwrote 86 instructions with data and the only revert available was a
 * click in the GUI.)
 *
 * <p>An undo is itself persisted: the auto-save already wrote the damage, so leaving the reverted
 * state only in memory would leave the file wrong.
 */
public class SaveTool implements ProgramTool {

	private static final List<String> OPS = List.of("save", "undo", "redo", "history");

	private static final long SAVE_TIMEOUT_MS = 20000;

	/** Guards against a typo'd count walking the whole stack back. */
	private static final int MAX_STEPS = 50;

	@Override
	public String name() {
		return "save";
	}

	@Override
	public String description() {
		return "Persistence and the undo stack. op=save (default) writes the program's edits to the " +
			"project now — edits auto-save after each tool call, but a busy program (background " +
			"analysis, or another writer) can defer that, so run this to flush them, e.g. before " +
			"restarting Ghidra. op=undo reverts the last tool call's transaction and saves the " +
			"result ('count' for more than one; each mutating tool call is exactly one transaction, " +
			"so undoing a bulk migrate takes all of it back). op=redo reapplies. op=history lists " +
			"what is on the undo/redo stacks, newest first — check it before undoing to confirm you " +
			"are reverting what you think. NOTE: the undo stack is in memory and does NOT survive a " +
			"Ghidra restart, while edits are already saved to disk — so undo a bad write BEFORE " +
			"restarting Ghidra, or it is unrecoverable.";
	}

	@Override
	public Map<String, Object> inputSchema() {
		return Map.of(
			"type", "object",
			"properties", Map.of(
				"op", Schemas.enumProp("What to do (default 'save')", OPS),
				"count", Schemas.intProp(
					"How many transactions to undo/redo (default 1, max " + MAX_STEPS + ")")));
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
	public McpSchema.CallToolResult execute(Map<String, Object> args, Program program)
			throws Exception {
		String op = Args.stringArg(args, "op", "save");
		if (!OPS.contains(op)) {
			return Results.error("op must be one of " + OPS);
		}
		return switch (op) {
			case "undo" -> step(program, args, true);
			case "redo" -> step(program, args, false);
			case "history" -> history(program);
			default -> save(program);
		};
	}

	private McpSchema.CallToolResult save(Program program) throws Exception {
		if (!program.isChanged()) {
			return Results.ok("No unsaved changes in " + program.getName());
		}
		boolean saved = ProjectContext.saveSettled(program, SAVE_TIMEOUT_MS);
		return saved
				? Results.ok("Saved " + program.getName())
				: Results.ok("Still busy (analysis running or another writer holds the lock) — " +
					program.getName() + "'s edits remain unsaved in memory; try again shortly.");
	}

	/**
	 * Undo or redo {@code count} transactions, then persist. Each step names the transaction it
	 * moved, so the caller can see exactly what was reverted rather than trusting a count.
	 */
	private McpSchema.CallToolResult step(Program program, Map<String, Object> args, boolean undo)
			throws Exception {
		String verb = undo ? "undo" : "redo";
		int count = Args.intArg(args, "count", 1);
		if (count < 1) {
			return Results.error("count must be at least 1");
		}
		if (count > MAX_STEPS) {
			return Results.error("count " + count + " exceeds the " + MAX_STEPS + "-step cap; " +
				"call repeatedly if you really mean to " + verb + " that far back");
		}
		if (undo ? !program.canUndo() : !program.canRedo()) {
			return Results.error("Nothing to " + verb + " on " + program.getName() +
				(undo ? " (the undo stack is empty — note it does not survive a Ghidra restart)"
						: ""));
		}

		List<String> moved = new ArrayList<>();
		for (int i = 0; i < count; i++) {
			// Read the name first: after the call it has moved to the other stack.
			String name = undo ? program.getUndoName() : program.getRedoName();
			if (undo ? !program.canUndo() : !program.canRedo()) {
				break;
			}
			if (undo) {
				program.undo();
			}
			else {
				program.redo();
			}
			moved.add(name);
		}

		// The bad write was already auto-saved, so the revert has to reach disk too.
		boolean saved = ProjectContext.saveSettled(program, SAVE_TIMEOUT_MS);

		StringBuilder sb = new StringBuilder(
			(undo ? "Undid " : "Redid ") + moved.size() + " transaction(s) on " + program.getName());
		for (String name : moved) {
			sb.append("\n  ").append(name);
		}
		if (!saved) {
			sb.append('\n').append(ProjectContext.SAVE_DEFERRED_NOTE);
		}
		if (moved.size() < count) {
			sb.append("\n(stack exhausted after ").append(moved.size()).append(" of ")
					.append(count).append(")");
		}
		return Results.ok(sb.toString());
	}

	private McpSchema.CallToolResult history(Program program) {
		List<String> undoNames = new ArrayList<>(program.getAllUndoNames());
		List<String> redoNames = new ArrayList<>(program.getAllRedoNames());
		if (undoNames.isEmpty() && redoNames.isEmpty()) {
			return Results.ok("Undo and redo stacks are empty for " + program.getName() +
				" (they start empty after each Ghidra restart, whatever is on disk).");
		}
		StringBuilder sb = new StringBuilder("Undo/redo history for " + program.getName() +
			" (newest first; lost on Ghidra restart):");
		sb.append("\nUndo (").append(undoNames.size()).append("):");
		append(sb, undoNames);
		sb.append("\nRedo (").append(redoNames.size()).append("):");
		append(sb, redoNames);
		return Results.ok(sb.toString());
	}

	private static void append(StringBuilder sb, List<String> names) {
		if (names.isEmpty()) {
			sb.append("\n  (empty)");
			return;
		}
		for (String name : names) {
			sb.append("\n  ").append(name);
		}
	}
}
