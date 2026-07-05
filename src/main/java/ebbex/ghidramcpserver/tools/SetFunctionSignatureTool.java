package ebbex.ghidramcpserver.tools;

import java.util.List;
import java.util.Map;

import ebbex.ghidramcpserver.McpToolDef;
import ebbex.ghidramcpserver.util.Decompilers;
import ebbex.ghidramcpserver.util.ProgramContext;
import ebbex.ghidramcpserver.util.Results;
import ebbex.ghidramcpserver.util.Transactions;
import ghidra.app.cmd.function.ApplyFunctionSignatureCmd;
import ghidra.app.cmd.function.FunctionRenameOption;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.util.parser.FunctionSignatureParser;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighFunctionDBUtil;
import ghidra.program.model.pcode.HighFunctionDBUtil.ReturnCommitOption;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.task.TaskMonitor;
import io.modelcontextprotocol.spec.McpSchema;

/**
 * Set a function's prototype. With a 'signature' this applies a full C prototype
 * (return type, name, parameters) in one call — renaming the function to match if
 * it still has a default name, and keeping its calling convention. Without a
 * 'signature' it commits the decompiler's inferred prototype instead.
 */
public class SetFunctionSignatureTool implements McpToolDef {

	private final Decompilers decompilers;

	public SetFunctionSignatureTool(Decompilers decompilers) {
		this.decompilers = decompilers;
	}

	@Override
	public String name() {
		return "set_function_signature";
	}

	@Override
	public String description() {
		return "Set a function's prototype. Pass a full C 'signature' like " +
			"'FILE *fopen(const char *path, const char *mode)' to apply return type + params in " +
			"one call (also renames the function if it still has a default FUN_ name, and keeps " +
			"its calling convention). Omit 'signature' to instead commit the decompiler's inferred " +
			"prototype (turns undefined(void) into the recovered parameters). Referenced types " +
			"must already exist — define them first with define_types.";
	}

	@Override
	public Map<String, Object> inputSchema() {
		return Map.of(
			"type", "object",
			"properties", Map.of(
				"function", Results.stringProp(
					"Target function: a name OR an address (alias: 'target'/'address')"),
				"address", Results.stringProp("Alias for 'function'"),
				"signature", Results.stringProp(
					"Full C prototype; omit to commit the decompiler-inferred prototype"),
				"calling_convention", Results.stringProp(
					"Optional calling convention name (e.g. __cdecl16far, __cdecl, __fastcall)")));
	}

	@Override
	public boolean isReadOnly() {
		return false;
	}

	@Override
	public McpSchema.CallToolResult execute(Map<String, Object> args, Program program)
			throws Exception {
		String functionRef = Results.locationArg(args);
		if (functionRef == null) {
			return Results.error("a function (name or address) is required");
		}
		Function function = ProgramContext.findFunction(program, functionRef);
		String signature = Results.stringArg(args, "signature", null);
		String callingConvention = Results.stringArg(args, "calling_convention", null);

		if (signature == null || signature.isBlank()) {
			return commitInferred(program, function, callingConvention);
		}
		return applyPrototype(program, function, signature, callingConvention);
	}

	private McpSchema.CallToolResult applyPrototype(Program program, Function function,
			String signature, String callingConvention) {
		FunctionDefinitionDataType definition;
		try {
			definition = new FunctionSignatureParser(program.getDataTypeManager(), null)
					.parse(function.getSignature(), normalizePrototype(signature));
		}
		catch (Exception e) {
			return Results.error("Could not parse signature '" + signature + "': " + e.getMessage() +
				". If a type name is unknown, define it first with define_types.");
		}
		if (definition == null) {
			return Results.error("Could not parse signature: " + signature);
		}

		return Transactions.modify(program, "Set function signature", () -> {
			if (callingConvention != null && !callingConvention.isBlank()) {
				function.setCallingConvention(callingConvention);
			}
			ApplyFunctionSignatureCmd cmd = new ApplyFunctionSignatureCmd(
				function.getEntryPoint(), definition, SourceType.USER_DEFINED,
				/*preserveCallingConvention*/ true, /*applyEmptyComposites*/ false,
				DataTypeConflictHandler.DEFAULT_HANDLER, FunctionRenameOption.RENAME_IF_DEFAULT);
			if (!cmd.applyTo(program, TaskMonitor.DUMMY)) {
				throw new IllegalStateException(cmd.getStatusMsg());
			}
			return "Applied signature to " + function.getName() + ": " +
				function.getSignature().getPrototypeString();
		});
	}

	/**
	 * Make a natural C prototype digestible to {@link FunctionSignatureParser}, which is
	 * fussy: it has no {@code const}/{@code volatile} and wants a pointer star bound to the
	 * return type (it mis-reads {@code FILE *fopen} as a name of {@code *fopen}). So strip
	 * qualifiers and move any star that sits against the function name onto the return type.
	 */
	static String normalizePrototype(String signature) {
		String s = signature.replaceAll("\\b(?:const|volatile)\\b", " ");
		int paren = s.indexOf('(');
		if (paren > 0) {
			String head = s.substring(0, paren);
			String tail = s.substring(paren);
			java.util.regex.Matcher m =
				java.util.regex.Pattern.compile("([A-Za-z_]\\w*)\\s*$").matcher(head);
			if (m.find()) {
				String name = m.group(1);
				String ret = head.substring(0, m.start()).replaceAll("\\s+", " ").trim();
				s = (ret.isEmpty() ? "" : ret + " ") + name + tail;
			}
		}
		return s.replaceAll("[ \\t]+", " ").trim();
	}

	private McpSchema.CallToolResult commitInferred(Program program, Function function,
			String callingConvention) {
		DecompileResults results = decompilers.decompile(program, function, 30);
		HighFunction high = results != null ? results.getHighFunction() : null;
		if (high == null) {
			return Results.error("Decompiler produced no high function for " + function.getName());
		}
		return Transactions.modify(program, "Commit inferred signature", () -> {
			if (callingConvention != null && !callingConvention.isBlank()) {
				function.setCallingConvention(callingConvention);
			}
			HighFunctionDBUtil.commitParamsToDatabase(high, true, ReturnCommitOption.COMMIT,
				SourceType.USER_DEFINED);
			return "Committed inferred prototype for " + function.getName() + ": " +
				function.getSignature().getPrototypeString();
		});
	}
}
