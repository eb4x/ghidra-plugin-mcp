package ebbex.ghidramcpserver.util;

import java.util.Map;

/** Readers for tool call arguments. */
public final class Args {

	private Args() {
	}

	public static String stringArg(Map<String, Object> args, String key, String defaultValue) {
		Object v = args.get(key);
		return v == null ? defaultValue : v.toString();
	}

	public static int intArg(Map<String, Object> args, String key, int defaultValue) {
		Object v = args.get(key);
		if (v == null) {
			return defaultValue;
		}
		if (v instanceof Number n) {
			return n.intValue();
		}
		return Integer.parseInt(v.toString());
	}

	/**
	 * A byte count or file offset: 64-bit, and accepting {@code 0x} hex as well as decimal.
	 * Both matter for the sizes this server deals in — {@link #intArg} would wrap a value past
	 * 2GB silently, and a caller who has just typed hex addresses all session will type
	 * {@code 0xd1000} here too, which {@code Integer.parseInt} rejects outright.
	 */
	public static long longArg(Map<String, Object> args, String key, long defaultValue) {
		Object v = args.get(key);
		if (v == null) {
			return defaultValue;
		}
		if (v instanceof Number n) {
			return n.longValue();
		}
		String s = v.toString().trim();
		boolean negative = s.startsWith("-");
		String digits = negative ? s.substring(1) : s;
		long magnitude = digits.regionMatches(true, 0, "0x", 0, 2)
				? Long.parseLong(digits.substring(2), 16)
				: Long.parseLong(digits);
		return negative ? -magnitude : magnitude;
	}

	public static boolean boolArg(Map<String, Object> args, String key, boolean defaultValue) {
		Object v = args.get(key);
		if (v == null) {
			return defaultValue;
		}
		if (v instanceof Boolean b) {
			return b;
		}
		return Boolean.parseBoolean(v.toString());
	}
}
