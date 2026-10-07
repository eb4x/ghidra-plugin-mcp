package ebbex.ghidramcpserver.util;

import java.util.List;
import java.util.Map;

/** Fragments for building tool input schemas (JSON Schema 2020-12 as plain maps). */
public final class Schemas {

	private Schemas() {
	}

	/** Schema fragment for a string property with a description. */
	public static Map<String, Object> stringProp(String description) {
		return Map.of("type", "string", "description", description);
	}

	/**
	 * Schema fragment for an integer property, accepted as a JSON integer or as a string of
	 * decimal digits. The string form exists for the same reason as {@link #sizeProp}'s: a
	 * client still holding a pre-restart schema sends a parameter it has never seen as a
	 * string, and the server validates arguments against its own schema before the tool
	 * runs, so a new integer parameter was unusable until every client reconnected. Read with
	 * {@link Args#intArg}, which parses the string.
	 */
	public static Map<String, Object> intProp(String description) {
		return Map.of("type", List.of("integer", "string"), "pattern", "^-?[0-9]+$",
			"description", description);
	}

	/**
	 * Schema fragment for a byte count or offset, accepted as a JSON integer <em>or</em> as a
	 * string so {@code "0xd1000"} works.
	 *
	 * <p>Declaring these {@code integer} alone made the tool's own promise of hex unkeepable:
	 * a schema-validating client refuses the string before the call is made, and a client
	 * holding a pre-restart schema — which is every client until it reconnects — sends unknown
	 * parameters as strings, so it fails validation even for a decimal value. Read with
	 * {@link Args#longArg}. Found by {@code ghidra-plugin-aeon}, which had to bypass its client
	 * and call over plain HTTP to get a block created at all.
	 */
	public static Map<String, Object> sizeProp(String description) {
		return Map.of("type", List.of("integer", "string"), "description", description);
	}

	/**
	 * Schema fragment for a boolean property, accepted as a JSON boolean or as the strings
	 * {@code "true"} / {@code "false"} — nothing else, so a client cannot send {@code "yes"}
	 * and get silently refused. The string form is for pre-reconnect clients (see
	 * {@link #intProp}): {@code regex=true} on {@code search_memory} was rejected with
	 * "string found, boolean expected" the first time madstools used it. Read with
	 * {@link Args#boolArg}.
	 */
	public static Map<String, Object> boolProp(String description) {
		return Map.of("type", List.of("boolean", "string"),
			"enum", List.of(true, false, "true", "false"), "description", description);
	}

	/** Schema fragment for a string enum property. */
	public static Map<String, Object> enumProp(String description, List<String> values) {
		return Map.of("type", "string", "description", description, "enum", values);
	}
}
