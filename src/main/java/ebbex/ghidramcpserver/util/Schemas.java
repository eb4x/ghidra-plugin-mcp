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

	/** Schema fragment for an integer property with a description. */
	public static Map<String, Object> intProp(String description) {
		return Map.of("type", "integer", "description", description);
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

	/** Schema fragment for a boolean property with a description. */
	public static Map<String, Object> boolProp(String description) {
		return Map.of("type", "boolean", "description", description);
	}

	/** Schema fragment for a string enum property. */
	public static Map<String, Object> enumProp(String description, List<String> values) {
		return Map.of("type", "string", "description", description, "enum", values);
	}
}
