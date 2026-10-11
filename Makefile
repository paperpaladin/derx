CC      = gcc
# -ffile-prefix-map is not optional: with -g, gcc writes its working directory
# into DWARF .debug_line_str, so the same source in two different directories
# produces two different binaries and the build stops being reproducible. It is
# on the non-debug CFLAGS too, so the flag cannot be lost by editing one line.
CFLAGS  = -std=c11 -O2 -Wall -Wextra -Wpedantic -ffile-prefix-map=$(CURDIR)=.

derx: derx.c
	$(CC) $(CFLAGS) -o $@ $<

test: derx overread
	t/run.sh ./derx

# The gate for the only heap buffer in the program. `slurp()` reallocs down to
# the file's exact size, and no assertion in t/run.sh can see whether it still
# does: while it over-allocated 64 KiB, a read one byte past a 1 KiB
# certificate was inside a live allocation and ASan said nothing, so
# `make test-asan` printed a clean run over an area smaller than it looked.
# This is a dependency of `test` and not a target somebody has to remember,
# because a gate nothing runs is a gate that does not exist.
#
# -DDERX_OVERREAD compiles a deliberate read of b[n] and this target FAILS
# unless ASan reports it. 86 is the witness: derx exits 0, 1 or 2 and nothing
# else, so the status cannot be confused with a clean refusal, a usage error
# or a segfault. The fixture is the two bytes 05 00, a DER NULL, which makes
# the exact allocation two bytes long and b[2] one past the end of it.
#
# Everything goes in a fresh mkdtemp. t/tmp is a fixed path that t/run.sh
# deletes on startup, so putting the probe binary there would mean two
# concurrent runs destroying each other.
overread: derx.c
	@W=$$(mktemp -d) || exit 1; \
	$(CC) -std=c11 -g -O1 -fsanitize=address -fno-omit-frame-pointer \
		-ffile-prefix-map=$(CURDIR)=. -DDERX_OVERREAD \
		-Wall -Wextra -Wpedantic -o "$$W/derx-overread" derx.c || \
		{ rm -rf "$$W"; exit 1; }; \
	printf '\005\000' > "$$W/null.der"; \
	ASAN_OPTIONS=exitcode=86 "$$W/derx-overread" parse "$$W/null.der" \
		> /dev/null 2> "$$W/log"; s=$$?; \
	if [ $$s -eq 86 ] && grep -q heap-buffer-overflow "$$W/log"; then \
		echo "ok    overread: ASan sees the planted read one byte past the file"; \
		rm -rf "$$W"; \
	else \
		echo "FAIL  overread: exit $$s, no heap-buffer-overflow reported."; \
		echo "      slurp() is over-allocating again, and every ASan run"; \
		echo "      in this suite is blind past the end of the input."; \
		sed 's/^/      | /' "$$W/log"; rm -rf "$$W"; exit 1; \
	fi

# A DER reader parses hostile bytes by definition, so the same suite has to
# pass with the sanitizers on. Separate binary so `make test` stays fast.
#
# exitcode=86 is load-bearing, not decoration. By default a sanitizer abort
# exits 1, and t/run.sh asserts exit 1 for "cleanly rejected this input" - so
# without this, test-asan silently could not fail: a heap overflow would score
# as a correct diagnostic. UBSan needs halt_on_error too, because it otherwise
# prints and keeps going. Copied from inflate, which found the collision the
# hard way.
SANOPT = ASAN_OPTIONS=exitcode=86 \
	 UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1:exitcode=86

test-asan: derx.c
	$(CC) -std=c11 -g -O1 -fsanitize=address,undefined -fno-omit-frame-pointer \
		-ffile-prefix-map=$(CURDIR)=. -Wall -Wextra -Wpedantic \
		-o derx-asan derx.c
	$(SANOPT) t/run.sh ./derx-asan

clean:
	rm -f derx derx-asan
	rm -rf t/tmp t/fuzz-fail t/fuzz.*/

.PHONY: test test-asan overread clean
