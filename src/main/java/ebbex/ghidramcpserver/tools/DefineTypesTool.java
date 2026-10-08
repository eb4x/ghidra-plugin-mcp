package ebbex.ghidramcpserver.tools;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import ebbex.ghidramcpserver.ProgramTool;
import ebbex.ghidramcpserver.util.Args;
import ebbex.ghidramcpserver.util.Results;
import ebbex.ghidramcpserver.util.Schemas;
import ebbex.ghidramcpserver.util.Transactions;
import ebbex.ghidramcpserver.util.Types;
import ghidra.app.util.cparser.C.CParser;
import ghidra.program.model.data.Array;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.Composite;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.EnumDataType;
import ghidra.program.model.data.FunctionDefinition;
import ghidra.program.model.data.ParameterDefinition;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.TypeDef;
import ghidra.program.model.data.TypedefDataType;
import ghidra.program.model.data.Union;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import io.modelcontextprotocol.spec.McpSchema;

/**
 * Define data types (structs, unions, typedefs, enums, function prototypes) into the program's
 * data type manager from a C source snippet.
 *
 * <p>The snippet is parsed <em>without</em> storing (CParser's {@code storeDataType=false}) and
 * the results are then resolved into the program by this tool. That ordering is the fix for a
 * trap in the storing mode: there, a body-less {@code struct X} is looked up only in the
 * parser's own table, never in the program, so it minted an empty {@code X} and stored it with
 * {@code REPLACE_HANDLER} over the caller's complete one &mdash; a 1538-byte record silently
 * became a 1-byte type, noticed only when the decompiler printed it as a char. In the non-storing
 * mode the parser binds the name to the existing type instead.
 *
 * <p>CParser also tokenises {@code __far}, {@code __ptr32} and {@code __near} and then discards
 * them, so no C spelling could ask for a pointer wider than the program's default (2 bytes in a
 * 16-bit program). The markers are recorded here before parsing and applied to the parsed types
 * afterwards.
 */
public class DefineTypesTool implements ProgramTool {

	/** Byte width of a {@code __far} / {@code __ptr32} pointer: 16-bit segment:offset. */
	private static final int FAR_POINTER_BYTES = 4;

	/** Spellings that make the declarator they modify a far pointer. */
	private static final Set<String> FAR_MARKERS = Set.of("__far", "far", "__ptr32");

	/** Words that may sit between a marker and the declarator's name without being it. */
	private static final Set<String> QUALIFIERS = Set.of("const", "volatile", "__near", "near",
		"__ptr64", "restrict", "__restrict", "__unaligned", "__cdecl", "__pascal", "__stdcall");

	private static final Pattern TOKEN = Pattern.compile("[A-Za-z_]\\w*|\\d\\w*|\\S");
	private static final Pattern COMMENTS = Pattern.compile("/\\*.*?\\*/|//[^\\n]*", Pattern.DOTALL);

	@Override
	public String name() {
		return "define_types";
	}

	@Override
	public String description() {
		return "Parse a C source snippet (structs, unions, typedefs, enums, function prototypes) " +
			"into the program's data type manager. Example: 'typedef struct { int handle; char " +
			"*buf; int flags; } FILE;'. A struct mentioned without a body ('struct X *p') binds " +
			"to the existing X; a full body for a name that already exists redefines that type " +
			"in place (everything using it sees the new layout) and the result says so with the " +
			"old and new size. Layouts follow natural alignment unless the snippet starts with " +
			"'#pragma pack(1)'. Pointer width follows the program (2 bytes in a 16-bit program): " +
			"write '__far *' (or 'far *', '__ptr32') for a 4-byte segment:offset pointer in a " +
			"field, typedef or parameter — the same thing the other tools' type strings spell " +
			"'T *32'. An enum is int-sized (2 bytes in a 16-bit program) unless declared with an " +
			"underlying type, 'enum Err : byte { … }' (any 1–8 byte integer type; " +
			"__attribute__((packed)) is accepted by Ghidra's parser and ignored). Each result " +
			"line gives the type's size; manage_types op=describe prints a full layout.";
	}

	@Override
	public Map<String, Object> inputSchema() {
		return Map.of(
			"type", "object",
			"properties", Map.of(
				"source", Schemas.stringProp("C declarations to parse into the program")),
			"required", List.of("source"));
	}

	@Override
	public boolean isReadOnly() {
		return false;
	}

	@Override
	public McpSchema.CallToolResult execute(Map<String, Object> args, Program program)
			throws Exception {
		String source = Args.stringArg(args, "source", null);
		if (source == null || source.isBlank()) {
			return Results.error("source is required");
		}
		EnumSizeScan sized = scanEnumSizes(source, program);
		FarScan scan = scanFarMarkers(sized.source());
		DataTypeManager dtm = program.getDataTypeManager();

		// The parse runs inside the transaction: in non-storing mode CParser still fills an
		// existing EMPTY composite in place (a placeholder from an earlier forward declaration).
		return Transactions.modify(program, "Define types", () -> {
			Set<String> placeholdersBefore = emptyComposites(dtm);
			CParser parser = new CParser(dtm, false, new DataTypeManager[0]);
			try {
				parser.parse(scan.source());
			}
			catch (Exception e) {
				throw new Exception("could not parse the C declarations: " + e.getMessage());
			}
			List<String> notes = new ArrayList<>();
			Map<String, DataType> typedefs = new TreeMap<>(parser.getTypes());
			applyFarMarkers(scan.marks(), parser, typedefs, dtm, notes);
			applyEnumSizes(sized.sizes(), parser);

			List<DataType> parsed = new ArrayList<>();
			parsed.addAll(new TreeMap<>(parser.getComposites()).values());
			parsed.addAll(typedefs.values());
			parsed.addAll(new TreeMap<>(parser.getEnums()).values());
			parsed.addAll(new TreeMap<>(parser.getFunctions()).values());
			// Judged before anything is stored: resolving one struct adds every type it refers
			// to, and a type this call created must not then read as "already identical".
			Map<String, DataType> existingBefore = new HashMap<>();
			for (DataType dt : parsed) {
				DataType existing = dtm.getDataType(dt.getCategoryPath(), dt.getName());
				if (existing != null) {
					existingBefore.put(dt.getPathName(), existing);
				}
			}
			List<String> lines = new ArrayList<>();
			Set<String> parsedComposites = parser.getComposites().keySet();
			Set<String> referenced = new HashSet<>();
			for (DataType dt : parsed) {
				lines.add(store(dtm, dt, existingBefore.get(dt.getPathName()), placeholdersBefore,
					parsedComposites, referenced));
			}
			StringBuilder sb = new StringBuilder();
			if (lines.isEmpty()) {
				sb.append("Parsed successfully, but no named types were produced.");
			}
			else {
				sb.append("Defined ").append(lines.size()).append(" type(s):\n  ")
						.append(String.join("\n  ", lines));
			}
			if (!referenced.isEmpty()) {
				sb.append("\nExisting types used as-is: ").append(String.join(", ", referenced));
			}
			for (String note : notes) {
				sb.append('\n').append(note);
			}
			return sb.toString();
		});
	}

	/**
	 * Resolve one parsed type into the program and describe what that did to the name:
	 * new, filled-in placeholder, unchanged, or redefined with the size it had before.
	 */
	private static String store(DataTypeManager dtm, DataType dt, DataType existing,
			Set<String> placeholdersBefore, Set<String> parsedComposites, Set<String> referenced) {
		String state;
		if (existing == null) {
			state = "new";
		}
		else if (placeholdersBefore.contains(existing.getPathName())) {
			state = "filled in (was an empty placeholder)";
		}
		else if (existing.isEquivalent(dt)) {
			state = "unchanged (already identical)";
		}
		else {
			state = "REDEFINED in place (was " + size(existing) + ")";
		}
		DataType stored = dtm.addDataType(dt, DataTypeConflictHandler.REPLACE_HANDLER);
		if (stored instanceof Composite composite) {
			collectReferenced(composite, parsedComposites, referenced);
		}
		return describe(stored) + "  " + state;
	}

	/** {@code struct RoomArt  1576 bytes (0x628), pack(1)}; typedefs and enums in their own shape. */
	private static String describe(DataType dt) {
		return switch (dt) {
			case Structure s -> "struct " + s.getName() + "  " + size(s) + ", " + packing(s) +
				(s.getNumDefinedComponents() == 0
						? "  — EMPTY: a forward declaration only; give it a body before applying it"
						: "");
			case Union u -> "union " + u.getName() + "  " + size(u) + ", " + packing(u);
			case TypeDef t -> "typedef " + t.getName() + " = " + t.getDataType().getName() +
				"  " + size(t);
			case FunctionDefinition f -> "function " + f.getName() + ": " +
				f.getPrototypeString();
			case ghidra.program.model.data.Enum e -> "enum " + e.getName() + "  " + size(e) +
				", " + e.getCount() + " values";
			default -> dt.getDisplayName() + "  " + size(dt);
		};
	}

	/** {@code 1576 (0x628) bytes}: decimal first, hex once it stops being obvious. */
	static String size(DataType dt) {
		if (dt instanceof Composite c && c.getNumDefinedComponents() == 0) {
			return "0 bytes";
		}
		int length = dt.getLength();
		if (length <= 0) {
			return "no fixed size";
		}
		return length + (length >= 16 ? " (0x" + Integer.toHexString(length) + ")" : "") +
			(length == 1 ? " byte" : " bytes");
	}

	static String packing(Composite composite) {
		if (!composite.isPackingEnabled()) {
			return "fixed offsets";
		}
		return composite.hasExplicitPackingValue()
				? "pack(" + composite.getExplicitPackingValue() + ")"
				: "natural alignment";
	}

	/** Path names of every composite with no fields: what a forward declaration leaves behind. */
	private static Set<String> emptyComposites(DataTypeManager dtm) {
		Set<String> empty = new HashSet<>();
		dtm.getAllComposites().forEachRemaining(c -> {
			if (c.getNumDefinedComponents() == 0) {
				empty.add(c.getPathName());
			}
		});
		return empty;
	}

	/** Composites this struct's fields reach (through pointers, arrays, typedefs) that the
	 * snippet itself did not define: the ones a body-less reference bound to. */
	private static void collectReferenced(Composite composite, Set<String> parsedComposites,
			Set<String> referenced) {
		for (DataTypeComponent component : composite.getDefinedComponents()) {
			DataType base = component.getDataType();
			while (true) {
				if (base instanceof Pointer p) {
					base = p.getDataType();
				}
				else if (base instanceof Array a) {
					base = a.getDataType();
				}
				else if (base instanceof TypeDef t) {
					base = t.getDataType();
				}
				else {
					break;
				}
			}
			if (base instanceof Composite c && !parsedComposites.contains(c.getName())) {
				referenced.add(c.getName() + " (" + size(c) + ")");
			}
		}
	}

	// ---- far pointer markers ------------------------------------------------------------

	/** A far marker's position: the composite or function it sat inside (null at top level)
	 * and the declarator name it modifies. */
	record FarMark(String owner, String name) {
	}

	/** The source with the markers blanked out, and where they were. */
	record FarScan(String source, List<FarMark> marks) {
	}

	/** {@code enum Name : base {}} with the base clause removed, and each enum's byte size. */
	record EnumSizeScan(String source, Map<String, Integer> sizes) {
	}

	/** {@code enum Name : uint8 {}: the C++11/C23 underlying-type clause Ghidra's parser lacks. */
	private static final Pattern ENUM_BASE =
		Pattern.compile("\\benum\\s+([A-Za-z_]\\w*)?\\s*:\\s*([A-Za-z_][\\w\\s*]*?)\\s*\\{");

	/**
	 * Ghidra's C parser sizes every enum to the data organization's int (2 bytes in a 16-bit
	 * program) or larger, and has no syntax to say otherwise: {@code enum X : uint8} is a parse
	 * error there and {@code __attribute__((packed))} is accepted and ignored. This reads the
	 * underlying-type clause off each enum, removes it so the parser sees plain C, and
	 * remembers the base type's size; {@link #applyEnumSizes} sets it after the parse.
	 *
	 * @throws IllegalArgumentException for an anonymous enum with a base clause (nothing to key
	 *             the size on), or a base type the program cannot resolve
	 */
	static EnumSizeScan scanEnumSizes(String source, Program program) {
		Matcher m = ENUM_BASE.matcher(COMMENTS.matcher(source).replaceAll(" "));
		Map<String, Integer> sizes = new HashMap<>();
		StringBuilder out = new StringBuilder();
		while (m.find()) {
			String name = m.group(1);
			String base = m.group(2).trim();
			if (name == null) {
				throw new IllegalArgumentException("'enum : " + base +
					"' needs a tag name to size: write 'enum Name : " + base + " { … }'");
			}
			DataType baseType;
			try {
				baseType = Types.parse(program, base);
			}
			catch (Exception e) {
				throw new IllegalArgumentException("enum " + name + ": base type '" + base +
					"' — " + e.getMessage());
			}
			if (baseType.getLength() < 1 || baseType.getLength() > 8) {
				throw new IllegalArgumentException("enum " + name + ": base type '" + base +
					"' is " + baseType.getLength() + " bytes; an enum is 1 to 8");
			}
			sizes.put(name, baseType.getLength());
			m.appendReplacement(out, Matcher.quoteReplacement("enum " + name + " {"));
		}
		m.appendTail(out);
		return new EnumSizeScan(sizes.isEmpty() ? source : out.toString(), sizes);
	}

	/**
	 * Resize the parsed enums to their declared base: the parser hands back
	 * {@link EnumDataType} instances, whose {@code setLength} refuses a size the values do not
	 * fit (the message says the minimum).
	 */
	private static void applyEnumSizes(Map<String, Integer> sizes, CParser parser)
			throws Exception {
		for (Map.Entry<String, Integer> entry : sizes.entrySet()) {
			DataType dt = parser.getEnums().get(entry.getKey());
			if (!(dt instanceof EnumDataType e)) {
				throw new Exception("enum " + entry.getKey() + " was declared with a base type " +
					"but the parser produced no enum of that name");
			}
			try {
				e.setLength(entry.getValue());
			}
			catch (IllegalArgumentException ex) {
				throw new Exception("enum " + entry.getKey() + " cannot be " + entry.getValue() +
					" byte(s): its values need at least " + e.getMinimumPossibleLength());
			}
		}
	}

	/**
	 * Find every {@code __far}/{@code far}/{@code __ptr32} and the declarator it belongs to,
	 * then remove it so the parser sees plain C. The declarator is the next identifier after the
	 * marker that is not a qualifier, which covers {@code T __far *name}, {@code T * __far name},
	 * {@code typedef T * __far Name} and parameters. The owner is the innermost {@code struct X {}
	 * / {@code union X {} body or {@code f(} parameter list the marker sits in. A bare {@code far}
	 * only counts next to a {@code *}, so a field that happens to be named {@code far} survives.
	 */
	static FarScan scanFarMarkers(String source) {
		String text = COMMENTS.matcher(source).replaceAll(" ");
		Matcher m = TOKEN.matcher(text);
		StringBuilder out = new StringBuilder();
		List<FarMark> marks = new ArrayList<>();
		Deque<String> owners = new ArrayDeque<>();
		String previousIdent = null;
		String compositeName = null;
		boolean afterStructKeyword = false;
		boolean farPending = false;
		int last = 0;
		while (m.find()) {
			String token = m.group();
			out.append(text, last, m.start());
			last = m.end();
			if (FAR_MARKERS.contains(token) && (!token.equals("far") || nextToStar(text, m))) {
				farPending = true;
				out.append(' ');
				continue;
			}
			out.append(token);
			switch (token) {
				case "struct", "union" -> {
					afterStructKeyword = true;
					compositeName = null;
				}
				case "{" -> {
					owners.push(compositeName == null ? "" : compositeName);
					afterStructKeyword = false;
					compositeName = null;
				}
				case "}", ")" -> {
					if (!owners.isEmpty()) {
						owners.pop();
					}
				}
				case "(" -> owners.push(previousIdent == null ? "" : previousIdent);
				case ";", "," -> {
					farPending = false;
					afterStructKeyword = false;
					compositeName = null;
				}
				default -> {
					if (!Character.isJavaIdentifierStart(token.charAt(0))) {
						break;
					}
					if (afterStructKeyword) {
						compositeName = token;
						afterStructKeyword = false;
					}
					else if (farPending && !QUALIFIERS.contains(token)) {
						String owner = owners.peek();
						marks.add(new FarMark(owner == null || owner.isEmpty() ? null : owner, token));
						farPending = false;
					}
					previousIdent = token;
				}
			}
		}
		out.append(text, last, text.length());
		return new FarScan(out.toString(), marks);
	}

	private static boolean nextToStar(String text, Matcher m) {
		int before = m.start() - 1;
		while (before >= 0 && Character.isWhitespace(text.charAt(before))) {
			before--;
		}
		int after = m.end();
		while (after < text.length() && Character.isWhitespace(text.charAt(after))) {
			after++;
		}
		return (before >= 0 && text.charAt(before) == '*') ||
			(after < text.length() && text.charAt(after) == '*');
	}

	/**
	 * Widen the pointers the markers named. Composites and functions are the parser's own
	 * (unstored) objects and are edited directly; a typedef is immutable, so a widened one
	 * replaces the parser's entry in {@code typedefs}.
	 */
	private static void applyFarMarkers(List<FarMark> marks, CParser parser,
			Map<String, DataType> typedefs, DataTypeManager dtm, List<String> notes) {
		if (marks.isEmpty()) {
			return;
		}
		List<String> applied = new ArrayList<>();
		for (FarMark mark : marks) {
			boolean done = mark.owner() == null
					? applyTopLevel(mark, parser, typedefs, dtm, applied)
					: applyOwned(mark, parser, dtm, applied);
			if (!done) {
				notes.add("⚠ far marker on '" + mark.name() + "'" +
					(mark.owner() == null ? "" : " in " + mark.owner()) +
					" matched no pointer declaration; it was left at the default width.");
			}
		}
		if (!applied.isEmpty()) {
			notes.add("Far pointers (" + FAR_POINTER_BYTES + " bytes): " +
				String.join(", ", applied));
		}
	}

	private static boolean applyTopLevel(FarMark mark, CParser parser,
			Map<String, DataType> typedefs, DataTypeManager dtm, List<String> applied) {
		DataType typedef = typedefs.get(mark.name());
		if (typedef instanceof TypeDef t) {
			DataType far = toFar(t.getDataType(), dtm);
			if (far == null) {
				return false;
			}
			typedefs.put(mark.name(),
				new TypedefDataType(t.getCategoryPath(), t.getName(), far, dtm));
			applied.add(mark.name());
			return true;
		}
		if (parser.getFunctions().get(mark.name()) instanceof FunctionDefinition f) {
			DataType far = toFar(f.getReturnType(), dtm);
			if (far == null) {
				return false;
			}
			f.setReturnType(far);
			applied.add(mark.name() + "() return");
			return true;
		}
		// A field of an anonymous composite has no owner name to match on.
		for (DataType dt : parser.getComposites().values()) {
			if (dt instanceof Composite c && c.getName().startsWith("anon_") &&
				widenField(c, mark.name(), dtm)) {
				applied.add(c.getName() + "." + mark.name());
				return true;
			}
		}
		return false;
	}

	private static boolean applyOwned(FarMark mark, CParser parser, DataTypeManager dtm,
			List<String> applied) {
		if (parser.getComposites().get(mark.owner()) instanceof Composite c &&
			widenField(c, mark.name(), dtm)) {
			applied.add(c.getName() + "." + mark.name());
			return true;
		}
		if (parser.getFunctions().get(mark.owner()) instanceof FunctionDefinition f) {
			ParameterDefinition[] params = f.getArguments();
			for (int i = 0; i < params.length; i++) {
				if (!mark.name().equals(params[i].getName())) {
					continue;
				}
				DataType far = toFar(params[i].getDataType(), dtm);
				if (far == null) {
					return false;
				}
				f.replaceArgument(i, params[i].getName(), far, params[i].getComment(),
					SourceType.USER_DEFINED);
				applied.add(f.getName() + "(" + mark.name() + ")");
				return true;
			}
		}
		return false;
	}

	private static boolean widenField(Composite composite, String field, DataTypeManager dtm) {
		DataTypeComponent[] components = composite.getDefinedComponents();
		for (int i = 0; i < components.length; i++) {
			DataTypeComponent component = components[i];
			if (!field.equals(component.getFieldName())) {
				continue;
			}
			DataType far = toFar(component.getDataType(), dtm);
			if (far == null) {
				return false;
			}
			if (composite instanceof Structure s) {
				s.replace(component.getOrdinal(), far, far.getLength(), component.getFieldName(),
					component.getComment());
			}
			else if (composite instanceof Union u) {
				u.delete(component.getOrdinal());
				u.insert(component.getOrdinal(), far, far.getLength(), component.getFieldName(),
					component.getComment());
			}
			return true;
		}
		return false;
	}

	/** The far version of a pointer (or array of pointers), or null if it is not a pointer. */
	private static DataType toFar(DataType dt, DataTypeManager dtm) {
		if (dt instanceof Pointer p) {
			return new PointerDataType(p.getDataType(), FAR_POINTER_BYTES, dtm);
		}
		if (dt instanceof Array a) {
			DataType element = toFar(a.getDataType(), dtm);
			return element == null ? null
					: new ArrayDataType(element, a.getNumElements(), element.getLength(), dtm);
		}
		return null;
	}
}
