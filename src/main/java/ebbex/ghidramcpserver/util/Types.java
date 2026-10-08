package ebbex.ghidramcpserver.util;

import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import ghidra.program.model.data.Array;
import ghidra.program.model.data.BuiltInDataType;
import ghidra.program.model.data.BuiltInDataTypeManager;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.CharDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.data.TypeDef;
import ghidra.program.model.listing.Program;
import ghidra.util.data.DataTypeParser;
import ghidra.util.data.DataTypeParser.AllowedDataTypes;

/**
 * One way to turn a type string into a {@link DataType}: Ghidra's {@link DataTypeParser} over
 * the program's own types and the built-ins, with a failure message that names the Ghidra
 * spellings for the width the caller evidently wanted. {@code uint8} is the common miss: Ghidra
 * has {@code uint16}, {@code uint32} and {@code uint64} but no {@code uint8} — the 1-byte
 * integers are {@code byte} and {@code sbyte}, and {@code uint8_t} exists only as a typedef in
 * the C library archives, which a program need not have.
 */
public final class Types {

	/** {@code uint8}, {@code int8_t}, {@code u8}-style spellings: the width the caller meant. */
	private static final Pattern WIDTH_SPELLING =
		Pattern.compile("(?i)^\\s*u?int(8|16|32|64)(?:_t)?\\s*(?:[*\\[].*)?$");

	private static final Map<String, String> NAMES_BY_WIDTH = Map.of(
		"8", "byte (unsigned), sbyte (signed); char, uchar and schar are 1 byte too but " +
			"print as character literals",
		"16", "short, ushort, int16, uint16, word",
		"32", "int, uint, int32, uint32, dword (long/ulong are 4 bytes in a 16-bit program)",
		"64", "longlong, ulonglong, int64, uint64, qword");

	/**
	 * The built-in names C headers typedef over. The built-in manager knows every built-in on a
	 * real program; under the test harness it has class-searched nothing, so these are listed.
	 */
	private static final Set<String> BUILTIN_NAMES = Set.of("byte", "sbyte", "word", "dword",
		"qword", "char", "uchar", "schar", "wchar_t", "bool", "short", "ushort", "int", "uint",
		"long", "ulong", "longlong", "ulonglong", "int16", "uint16", "int32", "uint32", "int64",
		"uint64", "float", "double", "longdouble", "void");

	private Types() {
	}

	/**
	 * Parse {@code text} against the program's types and the built-ins, as the other tools
	 * spell types: a name with optional {@code *}, {@code *32} and {@code [N]} suffixes.
	 *
	 * @throws Exception the parser's own, or one carrying its message plus the Ghidra names of
	 *             the width when the text spells one Ghidra has no built-in for
	 */
	public static DataType parse(Program program, String text) throws Exception {
		DataTypeManager dtm = program.getDataTypeManager();
		try {
			return new DataTypeParser(dtm, dtm, null, AllowedDataTypes.ALL).parse(text);
		}
		catch (Exception e) {
			String hint = widthHint(text);
			if (hint.isEmpty()) {
				throw e;
			}
			throw new Exception(e.getMessage() + hint, e);
		}
	}

	/**
	 * {@code byte (1 bytes)}, or {@code byte (1 bytes, typedef of uchar)} for a typedef, plus
	 * {@link #shadowNote} when the name is one a built-in also has.
	 */
	public static String describe(DataType dt) {
		String via = dt instanceof TypeDef t ? ", typedef of " + t.getBaseDataType().getName() : "";
		return dt.getName() + " (" + dt.getLength() + " bytes" + via + ")" + shadowNote(dt);
	}

	/**
	 * A program type whose name is also a built-in's wins every type string that spells the
	 * name, and a typedef of a char type is the surprising case: {@code typedef unsigned char
	 * byte} turns every {@code byte} into character literals in the decompiler. Pointers and
	 * arrays are judged by their element type.
	 *
	 * @return {@code " — shadows Ghidra's built-in byte: …"}, or "" when the type is the
	 *         built-in itself or no built-in has its name
	 */
	public static String shadowNote(DataType dt) {
		DataType element = dt;
		while (element instanceof Pointer || element instanceof Array) {
			element = element instanceof Pointer p ? p.getDataType() : ((Array) element).getDataType();
		}
		if (element == null || element instanceof BuiltInDataType) {
			return "";
		}
		if (!BUILTIN_NAMES.contains(element.getName()) && BuiltInDataTypeManager
				.getDataTypeManager().getDataType(CategoryPath.ROOT, element.getName()) == null) {
			return "";
		}
		DataType base = element instanceof TypeDef t ? t.getBaseDataType() : element;
		String chars = base instanceof CharDataType
				? ", a char type: the decompiler prints its values as character literals"
				: "";
		return " — shadows Ghidra's built-in " + element.getName() + ": '" + element.getName() +
			"' in a type string means the program's own " + element.getPathName() +
			(element instanceof TypeDef ? " = " + base.getName() : "") + chars;
	}

	/** "; Ghidra's 1-byte integers are: …" for a width spelling, or "". */
	public static String widthHint(String text) {
		if (text == null) {
			return "";
		}
		Matcher m = WIDTH_SPELLING.matcher(text);
		if (!m.matches()) {
			return "";
		}
		String bits = m.group(1);
		boolean stdint = text.toLowerCase(Locale.ROOT).contains("_t");
		if (!bits.equals("8") && !stdint) {
			return "";
		}
		return "; Ghidra has no built-in '" + text.trim().toLowerCase(Locale.ROOT) + "'" +
			(stdint ? " (the <stdint.h> names are typedefs in its C library archives, which " +
				"this program need not carry)" : "") +
			" — its " + (Integer.parseInt(bits) / 8) + "-byte integers are: " +
			NAMES_BY_WIDTH.get(bits);
	}
}
