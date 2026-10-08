package ebbex.ghidramcpserver.util;

import java.util.Locale;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
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
