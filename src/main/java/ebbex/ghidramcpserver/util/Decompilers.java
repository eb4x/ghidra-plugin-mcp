package ebbex.ghidramcpserver.util;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.program.model.listing.Program;

/**
 * Keeps one open {@link DecompInterface} per program. Decompiling different
 * programs runs in parallel (each interface is independent); concurrent calls
 * against the same program serialize on that interface's own synchronized
 * {@code decompileFunction}. Interfaces are held open until the plugin is
 * disposed (or the program is explicitly released) since opening one is costly.
 */
public class Decompilers {

	private final Map<Program, DecompInterface> byProgram = new ConcurrentHashMap<>();

	public DecompInterface get(Program program) {
		return byProgram.computeIfAbsent(program, Decompilers::open);
	}

	private static DecompInterface open(Program program) {
		DecompInterface di = new DecompInterface();
		DecompileOptions options = new DecompileOptions();
		options.grabFromProgram(program);
		di.setOptions(options);
		di.toggleCCode(true);
		di.toggleSyntaxTree(true);
		di.setSimplificationStyle("decompile");
		if (!di.openProgram(program)) {
			String message = di.getLastMessage();
			di.dispose();
			throw new IllegalStateException("Failed to open decompiler: " + message);
		}
		return di;
	}

	/** Dispose and forget the decompiler for one program (e.g. when its file is released). */
	public void release(Program program) {
		DecompInterface di = byProgram.remove(program);
		if (di != null) {
			di.dispose();
		}
	}

	public void dispose() {
		for (DecompInterface di : byProgram.values()) {
			try {
				di.dispose();
			}
			catch (Exception e) {
				// best effort on shutdown
			}
		}
		byProgram.clear();
	}
}
