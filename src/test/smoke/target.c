/*
 * The smoke-test sample for the MCP server: a freestanding x86-64 ELF that links against
 * nothing, so every byte in the binary is this file's (no libc, no crt start files).
 * Rebuild with build-sample.sh; the generated files next to it are what the smoke test runs.
 *
 * Symbols the smoke script relies on: _init (its rename chain), main, helper, mix and the
 * function-pointer table mcp_table (create kind=functions_from_table). main carries a loop so
 * the stripped twin clears FID's score threshold on its own (fid_build -> fid_apply).
 */
static int helper(int x) {
	return x * 3 + 1;
}

static int mix(int a, int b) {
	int r = 0;
	for (int i = 0; i < a; i++) {
		r += b ^ i;
	}
	return r;
}

void *mcp_table[2] = { (void *) helper, (void *) mix };

volatile int sink;

void _init(void) {
	sink = 7;
}

int main(int argc, char **argv) {
	int total = 0;
	for (int i = 0; i < argc; i++) {
		total += mix(helper(i), argc) + (argv[i] ? 1 : 0);
	}
	sink = helper(argc) + total;
	return total & 1;
}

static void sys_exit(int code) {
	__asm__ volatile ("syscall" : : "a"(60), "D"(code) : "rcx", "r11", "memory");
	for (;;) {
	}
}

void _start(void) {
	sys_exit(main(1, (char **) 0));
}
