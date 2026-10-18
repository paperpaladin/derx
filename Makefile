CC      = gcc
# -ffile-prefix-map is not optional: with -g, gcc writes its working directory
# into DWARF .debug_line_str, so the same source in two different directories
# produces two different binaries and the build stops being reproducible. It is
# on the non-debug CFLAGS too, so the flag cannot be lost by editing one line.
CFLAGS  = -std=c11 -O2 -Wall -Wextra -Wpedantic -ffile-prefix-map=$(CURDIR)=.

derx: derx.c
	$(CC) $(CFLAGS) -o $@ $<

test: derx
	t/run.sh ./derx

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

.PHONY: test test-asan clean
