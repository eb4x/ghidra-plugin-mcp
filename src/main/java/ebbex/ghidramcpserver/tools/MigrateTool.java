package ebbex.ghidramcpserver.tools;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

import ebbex.ghidramcpserver.ProgramTool;
import ebbex.ghidramcpserver.util.Args;
import ebbex.ghidramcpserver.util.ProjectContext;
import ebbex.ghidramcpserver.util.Results;
import ebbex.ghidramcpserver.util.Schemas;
import ebbex.ghidramcpserver.util.Transactions;
import ghidra.app.cmd.function.ApplyFunctionSignatureCmd;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.model.ProjectData;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.ReturnParameterImpl;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.symbol.SymbolType;
import ghidra.util.task.TaskMonitor;
import io.modelcontextprotocol.spec.McpSchema;

/**
 * Copy reverse-engineering documentation &mdash; function names and signatures, comments,
 * labels, data types, defined data &mdash; from another program in the same project into
 * this one. The use case is a <em>re-import</em>: a binary re-analyzed with an improved
 * analyzer starts bare, and the accumulated naming/typing work lives in the old DB.
 *
 * <p>This replaces the legacy python bridge's {@code merge_program_documentation}, whose
 * two failure modes are designed out rather than reproduced:
 *
 * <ul>
 * <li><b>It clobbered better names.</b> The legacy tool renamed a target function to the
 * source's name whenever both had a function and the names differed &mdash; which, after a
 * re-import with a <em>fixed</em> analyzer, dragged 157 correctly-named overlay stubs back to
 * their old wrong names. Two rules prevent that here: a <em>placeholder</em> source name (see
 * {@link #DEFAULT_PLACEHOLDER_PATTERN}) is never copied at all, which is precisely what those
 * stale {@code OVLSTUB_*} names are; and where both sides carry a meaningful name that disagrees,
 * the default {@code on_conflict=skip_named} keeps the target's and lists it for review.
 * {@code overwrite} lets the source win.</li>
 * <li><b>It skipped source-only functions silently.</b> Names land only where the target
 * already has a function at the same entry; functions that exist solely in the source (hand-made
 * in regions auto-analysis never reaches) were dropped without a word, and the {@code dry_run}
 * counts were correspondingly optimistic. Here they are counted and listed under
 * <em>source-only</em>, so the caller knows exactly what to re-create.</li>
 * </ul>
 *
 * <p>Addresses are matched by their string form, so overlay-qualified addresses
 * ({@code OVERLAY_00::010000}) map across DBs of the same binary. {@code dry_run=true} reports
 * the same counts without opening a transaction.
 */
public class MigrateTool implements ProgramTool {

	private static final List<String> KINDS =
		List.of("function_names", "signatures", "comments", "labels", "data_types", "data");

	private static final List<String> CONFLICT_MODES = List.of("skip_named", "overwrite");

	/** Where pre-migration snapshots land. */
	private static final String BACKUP_FOLDER = "/backups";

	/**
	 * Names that carry no information, so they are neither worth copying nor worth protecting.
	 * Ghidra's own {@link SourceType#DEFAULT} placeholders ({@code FUN_*}, {@code LAB_*}, …) are
	 * already identifiable by their source type, but an <em>analyzer</em> can assign an equally
	 * meaningless name at {@code ANALYSIS} source — RTLink's {@code OVL01_0000} /
	 * {@code OVLSTUB_20_0718} are placeholders spelled out of the address, and treating them as
	 * real names would block the very names a migration exists to carry. Extend via
	 * {@code placeholder_pattern}.
	 */
	private static final String DEFAULT_PLACEHOLDER_PATTERN =
		"(?i)^(FUN|LAB|DAT|UNK|SUB|EXT|caseD|switchD|OVL\\d+|OVLSTUB_\\d+)_[0-9A-F_]+$";

	private final ProjectContext context;

	public MigrateTool(ProjectContext context) {
		this.context = context;
	}

	@Override
	public String name() {
		return "migrate";
	}

	@Override
	public String description() {
		return "Copy documentation (function names, signatures, comments, labels, data types, " +
			"defined data) from another program in the project into this one — for carrying " +
			"naming/typing work across a re-import. 'source' is the source program's project " +
			"path; 'kinds' selects what to copy (default all). Only MEANINGFUL names move: a name " +
			"that is a placeholder (Ghidra's FUN_/LAB_/DAT_… plus anything matching " +
			"'placeholder_pattern', e.g. an analyzer's OVL01_0000) is never copied from the " +
			"source, and never protects a target. on_conflict=skip_named (default) keeps a " +
			"meaningful target name where the source disagrees — so a re-import's correctly-named " +
			"functions survive; on_conflict=overwrite lets the source win. Functions that exist " +
			"only in the source cannot receive names (nothing to name) and are reported as " +
			"'source-only' — re-create them, then re-run. dry_run=true reports what would change " +
			"without writing.";
	}

	@Override
	public Map<String, Object> inputSchema() {
		Map<String, Object> properties = new LinkedHashMap<>();
		properties.put("source", Schemas.stringProp(
			"Project path of the program to copy FROM, e.g. /VICEROY.OLD"));
		properties.put("kinds", Map.of(
			"type", "array",
			"description", "What to copy (default: all of " + KINDS + ")",
			"items", Map.of("type", "string", "enum", KINDS)));
		properties.put("on_conflict", Schemas.enumProp(
			"What to do where the target already has a MEANINGFUL name (default skip_named)",
			CONFLICT_MODES));
		properties.put("placeholder_pattern", Schemas.stringProp(
			"Java regex (case-insensitive, whole name) for names that carry no information, so " +
			"they are never copied and never protect a target. Default covers Ghidra's " +
			"placeholders plus address-spelled analyzer names: " + DEFAULT_PLACEHOLDER_PATTERN));
		properties.put("dry_run", Schemas.boolProp(
			"Report what would change without writing anything (default false)"));
		properties.put("snapshot", Schemas.boolProp(
			"Back the target program up before writing (default true). Ghidra drops its undo " +
			"history on every save and this server auto-saves each call, so the snapshot is the " +
			"only way back from a bad migration"));
		return Map.of("type", "object", "properties", properties,
			"required", List.of("source"));
	}

	@Override
	public boolean isReadOnly() {
		return false;
	}

	@Override
	public McpSchema.CallToolResult execute(Map<String, Object> args, Program target)
			throws Exception {
		String sourcePath = Args.stringArg(args, "source", null);
		if (sourcePath == null || sourcePath.isBlank()) {
			return Results.error("'source' (the project path to copy from) is required");
		}
		if (sourcePath.equals(target.getDomainFile().getPathname())) {
			return Results.error("'source' and 'program' are the same program (" + sourcePath + ")");
		}
		List<String> kinds = kinds(args.get("kinds"));
		for (String kind : kinds) {
			if (!KINDS.contains(kind)) {
				return Results.error("kinds must be drawn from " + KINDS + "; got '" + kind + "'");
			}
		}
		String onConflict = Args.stringArg(args, "on_conflict", "skip_named");
		if (!CONFLICT_MODES.contains(onConflict)) {
			return Results.error("on_conflict must be one of " + CONFLICT_MODES);
		}
		boolean dryRun = Args.boolArg(args, "dry_run", false);
		boolean overwrite = onConflict.equals("overwrite");

		Pattern placeholder;
		try {
			placeholder = Pattern.compile(
				Args.stringArg(args, "placeholder_pattern", DEFAULT_PLACEHOLDER_PATTERN));
		}
		catch (PatternSyntaxException e) {
			return Results.error("placeholder_pattern is not a valid regex: " + e.getMessage());
		}
		Names names = new Names(placeholder);

		Program source = context.openProgram(sourcePath);

		Report report = new Report();
		if (dryRun) {
			// Plan against the live DBs without a transaction: every applier checks its
			// precondition before mutating, so the dry run walks the same branches.
			migrate(source, target, kinds, overwrite, names, true, report);
			return Results.ok("DRY RUN — nothing written.\n" + report.render(sourcePath, kinds));
		}

		// Snapshot BEFORE writing. Ghidra discards its undo history on every save and this
		// server auto-saves after each call, so once a bad migration lands there is nothing
		// to undo — the backup is the only way back. Taken from the saved (pre-write) state.
		String backup = null;
		if (Args.boolArg(args, "snapshot", true)) {
			try {
				backup = snapshot(target);
			}
			catch (Exception e) {
				return Results.error("Refusing to migrate: could not snapshot '" +
					target.getDomainFile().getPathname() + "' first (" + e.getMessage() +
					"). Pass snapshot=false to migrate without a backup.");
			}
		}
		report.backup = backup;

		return Transactions.modify(target, "Migrate documentation from " + sourcePath, () -> {
			migrate(source, target, kinds, overwrite, names, false, report);
			return report.render(sourcePath, kinds);
		});
	}

	/** Copy the target's saved state to /backups, returning the new project path. */
	private static String snapshot(Program target) throws Exception {
		DomainFile file = target.getDomainFile();
		ProjectData data = file.getParent().getProjectData();
		DomainFolder backups = data.getFolder(BACKUP_FOLDER);
		if (backups == null) {
			backups = data.getRootFolder().createFolder(BACKUP_FOLDER.substring(1));
		}
		DomainFile copy = file.copyTo(backups, TaskMonitor.DUMMY);
		String stamp = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss"));
		return copy.setName(file.getName() + ".pre-migrate-" + stamp).getPathname();
	}

	private void migrate(Program source, Program target, List<String> kinds, boolean overwrite,
			Names names, boolean dryRun, Report report) throws Exception {
		// Always, whatever the kinds: a name, a signature and a comment can all land on a
		// function whose extent differs from the one they were written for.
		scanBodyMismatches(source, target, report);

		// Data types first: signatures and data definitions below resolve against them.
		if (kinds.contains("data_types")) {
			migrateDataTypes(source, target, dryRun, report);
		}
		if (kinds.contains("function_names") || kinds.contains("signatures")) {
			migrateFunctions(source, target, kinds, overwrite, names, dryRun, report);
		}
		if (kinds.contains("labels")) {
			migrateLabels(source, target, overwrite, names, dryRun, report);
		}
		if (kinds.contains("comments")) {
			migrateComments(source, target, overwrite, dryRun, report);
		}
		if (kinds.contains("data")) {
			migrateData(source, target, overwrite, dryRun, report);
		}
	}

	/**
	 * Report the functions the two DBs place at the same entry but give <em>different extents</em>.
	 *
	 * <p>Migration matches on the entry point, because that is the only stable key across a
	 * re-import. But <b>entry-point equality is not function equality</b>: when the two analyses
	 * disagree about where a function ends, the source's name, signature and comments are written
	 * onto a body they were never about. Observed on the real DBs, all silently:
	 *
	 * <ul>
	 * <li>{@code screen_redraw_full} — 38 bytes in the source, 67 in the target (the target
	 * absorbed what the source called a separate function). The migrated name describes half of
	 * what the function now does.</li>
	 * <li>{@code draw_map_tile} — a full ~1KB function in the source; in the target a <b>1-byte
	 * husk</b> whose code the analyzer never disassembled. A meticulous plate comment documenting
	 * the entire rendering algorithm was migrated onto a function containing no code.</li>
	 * </ul>
	 *
	 * <p>Nothing here is blocked: the documentation is still the best available and a mismatch is
	 * not automatically wrong. It is <em>reported</em>, worst first, because a silent skip is how
	 * this class of error hides — the same lesson as the data-vs-code clobber.
	 */
	private static void scanBodyMismatches(Program source, Program target, Report report) {
		for (Function sourceFunction : source.getFunctionManager().getFunctions(true)) {
			Address entry = translate(source, target, sourceFunction.getEntryPoint());
			Function targetFunction = entry == null
					? null
					: target.getFunctionManager().getFunctionAt(entry);
			if (targetFunction == null) {
				continue; // no counterpart: already reported as SOURCE-ONLY
			}
			long sourceBody = sourceFunction.getBody().getNumAddresses();
			long targetBody = targetFunction.getBody().getNumAddresses();
			if (sourceBody == targetBody) {
				continue;
			}
			report.bodyMismatches.add(new BodyMismatch(entry.toString(), sourceFunction.getName(),
				sourceBody, targetBody));
		}
	}

	/** One entry where both DBs have a function but disagree about how far it extends. */
	private record BodyMismatch(String entry, String name, long sourceBody, long targetBody) {

		/** A target body this small holds no real code — the analyzer failed to disassemble it. */
		boolean targetIsHusk() {
			return targetBody <= 1;
		}

		long delta() {
			return Math.abs(sourceBody - targetBody);
		}

		String render() {
			String note = targetIsHusk()
					? "  <-- TARGET IS A HUSK: its code was never disassembled; the migrated " +
						"name/comments describe code that is not there"
					: "";
			return entry + "  " + name + ": source " + sourceBody + "B, target " + targetBody +
				"B" + note;
		}
	}

	/**
	 * Function names and signatures. A source name that is a placeholder carries no information,
	 * so it is never copied — that alone defuses the legacy tool's worst behavior, since the old
	 * DB's stale {@code OVLSTUB_*} names can no longer overwrite the re-import's correct ones. A
	 * target whose name is <em>meaningful</em> is left alone unless {@code overwrite}; a target
	 * still wearing a placeholder is free to receive the source's name. Source functions with no
	 * counterpart in the target are recorded rather than skipped in silence — that omission is
	 * what made the legacy tool's dry-run counts lie.
	 */
	private void migrateFunctions(Program source, Program target, List<String> kinds,
			boolean overwrite, Names names, boolean dryRun, Report report) throws Exception {
		boolean doNames = kinds.contains("function_names");
		boolean doSignatures = kinds.contains("signatures");

		for (Function sourceFunction : source.getFunctionManager().getFunctions(true)) {
			Address entry = translate(source, target, sourceFunction.getEntryPoint());
			Function targetFunction = entry == null
					? null
					: target.getFunctionManager().getFunctionAt(entry);
			if (targetFunction == null) {
				// No function at this entry in the target: there is nothing to rename. The caller
				// must re-create the body first (see the class javadoc), so name it explicitly.
				if (names.isMeaningful(sourceFunction.getSymbol())) {
					report.sourceOnly.add(sourceFunction.getEntryPoint() + "  " +
						sourceFunction.getName());
				}
				continue;
			}

			if (doNames && names.isMeaningful(sourceFunction.getSymbol())) {
				if (sourceFunction.getName().equals(targetFunction.getName())) {
					report.namesAlreadyEqual++;
				}
				else if (names.isMeaningful(targetFunction.getSymbol()) && !overwrite) {
					report.namesSkippedNamed.add(entry + "  target '" + targetFunction.getName() +
						"' kept, source had '" + sourceFunction.getName() + "'");
				}
				else {
					if (!dryRun) {
						targetFunction.setName(sourceFunction.getName(), SourceType.USER_DEFINED);
					}
					report.namesApplied++;
				}
			}

			if (doSignatures && sourceFunction.getSignatureSource() != SourceType.DEFAULT) {
				if (sourceFunction.hasCustomVariableStorage()) {
					// A C prototype cannot express pinned register/stack storage, so the
					// ApplyFunctionSignatureCmd path below would re-derive it from the calling
					// convention and decompile the function WRONG (params/return at the default
					// offsets) without any error. Carry the exact storage instead. This is the
					// whole point of the fix: 18 of VICEROY's 95 signatures are custom-storage
					// (long params, far-pointer returns in DX:AX) and all silently regressed.
					try {
						if (!dryRun) {
							applyCustomStorage(target, targetFunction, sourceFunction);
						}
						report.signaturesApplied++;
						report.signaturesCustomStorage++;
					}
					catch (Exception e) {
						report.signaturesCustomStorageFailed.add(entry + "  " +
							sourceFunction.getName() + ": " + e.getMessage());
					}
				}
				else if (!dryRun) {
					// ApplyFunctionSignatureCmd resolves the source's types into the target's
					// DataTypeManager, so this works across DBs without pre-copying types.
					FunctionDefinitionDataType definition =
						new FunctionDefinitionDataType(sourceFunction, false);
					ApplyFunctionSignatureCmd cmd = new ApplyFunctionSignatureCmd(entry, definition,
						SourceType.USER_DEFINED);
					if (!cmd.applyTo(target, TaskMonitor.DUMMY)) {
						report.signaturesFailed++;
						continue;
					}
					report.signaturesApplied++;
				}
				else {
					report.signaturesApplied++;
				}
			}
		}
	}

	/**
	 * Carry a function's <em>custom variable storage</em> across DBs verbatim — the pinned
	 * register/stack location of each parameter and the return.
	 *
	 * <p>{@link VariableStorage#getSerializationString()} is the same program-relative encoding
	 * Ghidra persists in the DB, and both DBs are the same binary/architecture, so it
	 * deserializes cleanly into the target. Data types resolve into the target's manager the same
	 * way the C-prototype path relies on. Applied with {@code CUSTOM_STORAGE} so Ghidra keeps the
	 * exact storage instead of re-deriving it from the calling convention.
	 */
	private static void applyCustomStorage(Program target, Function targetFunction,
			Function sourceFunction) throws Exception {
		DataTypeManager targetTypes = target.getDataTypeManager();
		List<Variable> params = new ArrayList<>();
		for (Parameter parameter : sourceFunction.getParameters()) {
			DataType type =
				targetTypes.resolve(parameter.getDataType(), DataTypeConflictHandler.KEEP_HANDLER);
			VariableStorage storage = VariableStorage.deserialize(target,
				parameter.getVariableStorage().getSerializationString());
			params.add(new ParameterImpl(parameter.getName(), type, storage, target));
		}
		Parameter sourceReturn = sourceFunction.getReturn();
		DataType returnType =
			targetTypes.resolve(sourceReturn.getDataType(), DataTypeConflictHandler.KEEP_HANDLER);
		VariableStorage returnStorage = VariableStorage.deserialize(target,
			sourceReturn.getVariableStorage().getSerializationString());
		Variable returnVar = new ReturnParameterImpl(returnType, returnStorage, target);
		targetFunction.updateFunction(sourceFunction.getCallingConventionName(), returnVar, params,
			Function.FunctionUpdateType.CUSTOM_STORAGE, true, SourceType.USER_DEFINED);
	}

	/** Non-dynamic, non-function labels (function symbols are handled as functions). */
	private void migrateLabels(Program source, Program target, boolean overwrite, Names names,
			boolean dryRun, Report report) throws Exception {
		SymbolTable targetSymbols = target.getSymbolTable();
		for (Symbol symbol : source.getSymbolTable().getAllSymbols(false)) {
			if (symbol.getSymbolType() != SymbolType.LABEL || !names.isMeaningful(symbol)) {
				continue;
			}
			Address address = translate(source, target, symbol.getAddress());
			if (address == null) {
				continue;
			}
			Symbol existing = targetSymbols.getPrimarySymbol(address);
			if (existing != null && existing.getName().equals(symbol.getName())) {
				report.labelsAlreadyEqual++;
				continue;
			}
			if (names.isMeaningful(existing) && !overwrite) {
				report.labelsSkippedNamed++;
				continue;
			}
			if (!dryRun) {
				targetSymbols.createLabel(address, symbol.getName(), SourceType.USER_DEFINED);
			}
			report.labelsApplied++;
		}
	}

	/** Every comment type at every commented address. An existing target comment wins unless overwrite. */
	private void migrateComments(Program source, Program target, boolean overwrite, boolean dryRun,
			Report report) {
		Listing sourceListing = source.getListing();
		Listing targetListing = target.getListing();
		for (CommentType type : CommentType.values()) {
			AddressIterator it =
				sourceListing.getCommentAddressIterator(type, source.getMemory(), true);
			while (it.hasNext()) {
				Address sourceAddress = it.next();
				String comment = sourceListing.getComment(type, sourceAddress);
				if (comment == null || comment.isBlank()) {
					continue;
				}
				Address address = translate(source, target, sourceAddress);
				if (address == null) {
					continue;
				}
				String existing = targetListing.getComment(type, address);
				if (comment.equals(existing)) {
					report.commentsAlreadyEqual++;
					continue;
				}
				if (existing != null && !existing.isBlank() && !overwrite) {
					report.commentsSkippedExisting++;
					continue;
				}
				if (!dryRun) {
					targetListing.setComment(address, type, comment);
				}
				report.commentsApplied++;
			}
		}
	}

	/**
	 * Copy the source's data types. {@code KEEP_HANDLER} leaves an existing target type of the
	 * same name untouched, so this fills gaps and never rewrites the target's own definitions.
	 */
	private void migrateDataTypes(Program source, Program target, boolean dryRun, Report report) {
		DataTypeManager sourceTypes = source.getDataTypeManager();
		DataTypeManager targetTypes = target.getDataTypeManager();
		for (DataType dataType : iterable(sourceTypes.getAllDataTypes())) {
			if (dataType.getSourceArchive() != null &&
				!dataType.getSourceArchive().equals(sourceTypes.getLocalSourceArchive())) {
				// Types owned by an archive (builtins, imported .gdt) come back with the archive,
				// not with a migration; copying them would fork them from their source.
				continue;
			}
			if (targetTypes.getDataType(dataType.getCategoryPath(), dataType.getName()) != null) {
				report.dataTypesAlreadyPresent++;
				continue;
			}
			if (!dryRun) {
				targetTypes.addDataType(dataType, DataTypeConflictHandler.KEEP_HANDLER);
			}
			report.dataTypesApplied++;
		}
	}

	/**
	 * Defined data: apply the source's type where the target has no <em>code</em> and no
	 * conflicting data.
	 *
	 * <p><b>Data never overwrites an instruction.</b> The source is an older analysis, so it holds
	 * data at addresses the current analyzer has since correctly recovered as code; laying the old
	 * data over them destroys the instruction and every reference it carried. This is not
	 * hypothetical — the first real run of this tool did exactly that, clearing a
	 * {@code CALLF OVLSTUB_30_0608} at {@code 1000:0048} into a {@code uint} and silently costing
	 * the stub a caller. The trap: {@link Listing#getDefinedDataAt} returns null for an
	 * instruction, so an "is anything here?" check written against it sees an empty address and
	 * clears the code unit. Ask the listing what <em>code unit</em> is there instead, and never
	 * clear an instruction — not even under {@code overwrite}, whose job is to arbitrate
	 * documentation, not to undo disassembly.
	 */
	private void migrateData(Program source, Program target, boolean overwrite, boolean dryRun,
			Report report) throws Exception {
		Listing targetListing = target.getListing();
		for (Data sourceData : iterable(source.getListing().getDefinedData(true))) {
			Address address = translate(source, target, sourceData.getAddress());
			if (address == null) {
				continue;
			}
			if (targetListing.getInstructionContaining(address) != null) {
				// The target disassembled this as code. Trust the newer analysis, keep the
				// instruction, and tell the caller where the two DBs disagree.
				report.dataSkippedCode.add(address + "  source has " +
					sourceData.getDataType().getName() + ", target has code");
				continue;
			}
			Data existing = targetListing.getDefinedDataAt(address);
			if (existing != null) {
				if (existing.getDataType().isEquivalent(sourceData.getDataType())) {
					report.dataAlreadyEqual++;
					continue;
				}
				if (!overwrite) {
					report.dataSkippedExisting++;
					continue;
				}
			}
			if (!dryRun) {
				DataType resolved = target.getDataTypeManager()
						.resolve(sourceData.getDataType(), DataTypeConflictHandler.KEEP_HANDLER);
				try {
					// Only undefined bytes or existing data lie in this range (code was ruled out
					// above), so clearing is safe — it drops no disassembly.
					Address end = address.add(Math.max(0, resolved.getLength() - 1));
					if (targetListing.getInstructionContaining(end) != null ||
						crossesCode(targetListing, address, end)) {
						report.dataSkippedCode.add(address + "  source has " +
							resolved.getName() + ", target has code within its extent");
						continue;
					}
					targetListing.clearCodeUnits(address, end, false);
					targetListing.createData(address, resolved);
				}
				catch (Exception e) {
					// Conflicting layout at this address in the target — count it rather than
					// abort the migration.
					report.dataFailed++;
					continue;
				}
			}
			report.dataApplied++;
		}
	}

	/** True if any instruction lies in [start, end] — a multi-byte type must not straddle code. */
	private static boolean crossesCode(Listing listing, Address start, Address end) {
		for (Address at = start; at.compareTo(end) <= 0; at = at.next()) {
			if (at == null) {
				return false;
			}
			if (listing.getInstructionContaining(at) != null) {
				return true;
			}
		}
		return false;
	}

	/**
	 * The same physical address in the target's factory. Both DBs are the same binary, so the
	 * address <em>string</em> (including any {@code OVERLAY_xx::} qualifier) is the stable key;
	 * a source address whose space does not exist in the target yields null and is skipped.
	 */
	private static Address translate(Program source, Program target, Address address) {
		if (source.getAddressFactory().equals(target.getAddressFactory())) {
			return address;
		}
		try {
			return target.getAddressFactory().getAddress(address.toString());
		}
		catch (Exception e) {
			return null;
		}
	}

	/**
	 * Decides which names say something. A name is meaningful when a human or an analyzer chose
	 * it <em>and</em> it is not one of the address-spelled placeholder forms — the distinction
	 * {@link SourceType} alone cannot make, because an analyzer's {@code OVL01_0000} is assigned
	 * at {@code ANALYSIS} source yet says no more than Ghidra's own {@code FUN_*}.
	 */
	private record Names(Pattern placeholder) {

		boolean isMeaningful(Symbol symbol) {
			if (symbol == null || symbol.isDynamic() ||
				symbol.getSource() == SourceType.DEFAULT) {
				return false;
			}
			return !placeholder.matcher(symbol.getName()).matches();
		}
	}

	@SuppressWarnings("unchecked")
	private static List<String> kinds(Object value) {
		if (value instanceof List<?> list && !list.isEmpty()) {
			List<String> kinds = new ArrayList<>();
			for (Object item : (List<Object>) list) {
				kinds.add(String.valueOf(item));
			}
			return kinds;
		}
		return KINDS;
	}

	private static <T> Iterable<T> iterable(java.util.Iterator<T> it) {
		return () -> it;
	}

	/** Counts and the two lists a caller must act on: source-only functions and kept names. */
	private static final class Report {
		int namesApplied;
		int namesAlreadyEqual;
		int signaturesApplied;
		int signaturesCustomStorage;
		int signaturesFailed;
		int labelsApplied;
		int labelsAlreadyEqual;
		int labelsSkippedNamed;
		int commentsApplied;
		int commentsAlreadyEqual;
		int commentsSkippedExisting;
		int dataTypesApplied;
		int dataTypesAlreadyPresent;
		int dataApplied;
		int dataAlreadyEqual;
		int dataSkippedExisting;
		int dataFailed;
		final List<String> sourceOnly = new ArrayList<>();
		final List<String> namesSkippedNamed = new ArrayList<>();
		final List<String> signaturesCustomStorageFailed = new ArrayList<>();
		final List<String> dataSkippedCode = new ArrayList<>();
		final List<BodyMismatch> bodyMismatches = new ArrayList<>();

		String backup;

		String render(String sourcePath, List<String> kinds) {
			StringBuilder sb = new StringBuilder("Migrated from " + sourcePath + "  (kinds: " +
				String.join(", ", kinds) + ")");
			if (backup != null) {
				sb.append("\nBackup:          ").append(backup)
						.append("  (restore: manage_files delete this program, then op=copy the ")
						.append("backup back and rename it)");
			}
			if (kinds.contains("function_names")) {
				sb.append("\nFunction names:  ").append(namesApplied).append(" applied, ")
						.append(namesAlreadyEqual).append(" already equal, ")
						.append(namesSkippedNamed.size()).append(" kept (target already named)");
			}
			if (kinds.contains("signatures")) {
				sb.append("\nSignatures:      ").append(signaturesApplied).append(" applied");
				if (signaturesCustomStorage > 0) {
					sb.append(" (").append(signaturesCustomStorage)
							.append(" with custom register/stack storage carried verbatim)");
				}
				if (signaturesFailed > 0) {
					sb.append(", ").append(signaturesFailed).append(" failed");
				}
				if (!signaturesCustomStorageFailed.isEmpty()) {
					sb.append(", ").append(signaturesCustomStorageFailed.size())
							.append(" custom-storage NOT carried (see below)");
				}
			}
			if (kinds.contains("labels")) {
				sb.append("\nLabels:          ").append(labelsApplied).append(" applied, ")
						.append(labelsAlreadyEqual).append(" already equal, ")
						.append(labelsSkippedNamed).append(" kept");
			}
			if (kinds.contains("comments")) {
				sb.append("\nComments:        ").append(commentsApplied).append(" applied, ")
						.append(commentsAlreadyEqual).append(" already equal, ")
						.append(commentsSkippedExisting).append(" kept");
			}
			if (kinds.contains("data_types")) {
				sb.append("\nData types:      ").append(dataTypesApplied).append(" added, ")
						.append(dataTypesAlreadyPresent).append(" already present");
			}
			if (!bodyMismatches.isEmpty()) {
				long husks = bodyMismatches.stream().filter(BodyMismatch::targetIsHusk).count();
				sb.append("\nBody mismatch:   ").append(bodyMismatches.size())
						.append(" function(s) differ in extent between the DBs");
				if (husks > 0) {
					sb.append(", ").append(husks).append(" of them HUSKS (see below)");
				}
			}
			if (kinds.contains("data")) {
				sb.append("\nDefined data:    ").append(dataApplied).append(" applied, ")
						.append(dataAlreadyEqual).append(" already equal, ")
						.append(dataSkippedExisting).append(" kept, ")
						.append(dataSkippedCode.size()).append(" refused (target has code)");
				if (dataFailed > 0) {
					sb.append(", ").append(dataFailed).append(" failed (conflicting layout)");
				}
			}

			if (!sourceOnly.isEmpty()) {
				sb.append("\n\nSOURCE-ONLY functions (").append(sourceOnly.size())
						.append(") — no function at that entry in the target, so their names could ")
						.append("NOT be applied. Re-create them (create kind=function with ")
						.append("end_address), then re-run migrate:");
				appendCapped(sb, sourceOnly, 40);
			}
			if (!bodyMismatches.isEmpty()) {
				long husks = bodyMismatches.stream().filter(BodyMismatch::targetIsHusk).count();
				sb.append("\n\nBODY MISMATCH (").append(bodyMismatches.size())
						.append(husks > 0 ? ", including " + husks + " HUSK(S)" : "")
						.append(") — both DBs have a function at these entries, but they disagree ")
						.append("about how far it extends. The name/signature/comments were applied ")
						.append("anyway, because the ENTRY matched — but entry-point equality is not ")
						.append("function equality, so documentation written for one body may now ")
						.append("describe different code. Worst first:");
				// Worst first: a husk, or a large delta, is what a reader must look at.
				List<String> lines = bodyMismatches.stream()
						.sorted(Comparator.comparing(BodyMismatch::targetIsHusk).reversed()
								.thenComparing(Comparator.comparingLong(BodyMismatch::delta)
										.reversed()))
						.map(BodyMismatch::render)
						.toList();
				appendCapped(sb, lines, 25);
			}
			if (!dataSkippedCode.isEmpty()) {
				sb.append("\n\nDATA REFUSED (").append(dataSkippedCode.size())
						.append(") — the source (an older analysis) has data where THIS program has ")
						.append("instructions. The data was NOT applied: overwriting an instruction ")
						.append("would destroy it and every reference it carries. The newer ")
						.append("disassembly is kept. If a site here is genuinely data, clear the ")
						.append("code there deliberately (clear kind=code) and re-run:");
				appendCapped(sb, dataSkippedCode, 40);
			}
			if (!signaturesCustomStorageFailed.isEmpty()) {
				sb.append("\n\nCUSTOM STORAGE NOT CARRIED (").append(signaturesCustomStorageFailed.size())
						.append(") — these functions pin register/stack storage the target could not ")
						.append("reconstruct, so their prototype was left as-is rather than applied ")
						.append("WRONG. A silent re-derivation is exactly this tool's worst failure; ")
						.append("re-pin them by hand with set_function_signature parameters[].storage:");
				appendCapped(sb, signaturesCustomStorageFailed, 40);
			}
			if (!namesSkippedNamed.isEmpty()) {
				sb.append("\n\nKEPT target names (").append(namesSkippedNamed.size())
						.append(") — both sides have a meaningful name and they disagree, so ")
						.append("on_conflict=skip_named kept the target's. Review these: after a ")
						.append("re-import with a fixed analyzer the target is usually right, but ")
						.append("on_conflict=overwrite lets the source win:");
				appendCapped(sb, namesSkippedNamed, 40);
			}
			return sb.toString();
		}

		private static void appendCapped(StringBuilder sb, List<String> lines, int cap) {
			int shown = Math.min(lines.size(), cap);
			for (int i = 0; i < shown; i++) {
				sb.append("\n  ").append(lines.get(i));
			}
			if (lines.size() > shown) {
				sb.append("\n  … ").append(lines.size() - shown).append(" more");
			}
		}
	}
}
