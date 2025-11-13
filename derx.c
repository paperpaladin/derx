/*
 * derx - ASN.1 DER reader and X.509 certificate printer.
 *
 *   derx parse FILE    the DER structure: offset, depth, header length,
 *                      length, constructed/primitive, tag, value
 *   derx cert  FILE     X.509 certificate fields
 *
 * FILE of "-" reads stdin. Input is DER; there is no base64 decoder here.
 *
 * The authority on correctness is /usr/bin/openssl, not this code. `derx
 * parse` is written to be byte-identical to `openssl asn1parse -i -inform DER`
 * on every input that is valid DER, so the test is a diff rather than a
 * collection of expectations I wrote down myself. Where derx is deliberately
 * stricter than openssl -- openssl reads BER, we read DER -- t/run.sh asserts
 * that divergence explicitly instead of hiding it. See t/run.sh and README.md.
 *
 * Copyright (C) 2026  PLACEHOLDER.  Licensed under the GPLv3 (see LICENSE).
 */
#define _POSIX_C_SOURCE 200809L
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * One rejection path, on purpose. "derx rejected this input" and "derx
 * crashed" have to stay distinguishable from outside, because the whole
 * robustness claim is that the first happens and the second does not; a
 * second way out of the program is a second thing for the harness to be
 * confused by. Everything that is not valid DER ends here, status 1.
 */
static void die(const char *fmt, ...) {
	va_list ap;
	va_start(ap, fmt);
	fputs("derx: ", stderr);
	vfprintf(stderr, fmt, ap);
	fputc('\n', stderr);
	va_end(ap);
	exit(1);
}

/* ------------------------------------------------------------------ input */

/* shortcut: the whole file is read into one buffer, so a DER object larger
 * than RAM cannot be parsed at all. Certificates are kilobytes and the
 * offsets printed by asn1parse are absolute, so streaming would buy nothing
 * here; the upgrade path is a windowed reader keyed on the fact that a
 * definite length tells you up front how far the element reaches. */
static uint8_t *slurp(const char *path, size_t *outn) {
	FILE *f = strcmp(path, "-") == 0 ? stdin : fopen(path, "rb");
	if (!f) die("cannot open %s", path);
	size_t cap = 1u << 16, n = 0;
	uint8_t *p = malloc(cap);
	if (!p) die("out of memory");
	for (;;) {
		if (n == cap) {
			cap *= 2;
			uint8_t *q = realloc(p, cap);
			if (!q) die("out of memory");
			p = q;
		}
		size_t got = fread(p + n, 1, cap - n, f);
		n += got;
		if (got == 0) break;
	}
	if (ferror(f)) die("read error on %s", path);
	if (f != stdin) fclose(f);
	*outn = n;
	return p;
}

/* ------------------------------------------------------------ tag decoding */

#define CLS_UNIV 0
#define CLS_APPL 1
#define CLS_CONT 2
#define CLS_PRIV 3

typedef struct {
	size_t off;  /* offset of the identifier octet */
	size_t hl;   /* identifier + length octets */
	size_t len;  /* content length */
	unsigned cls;
	unsigned tag;
	int cons;    /* constructed */
} Hdr;

/*
 * Decode one identifier-and-length at `off`. `end` is the end of the
 * *enclosing* element, not of the file: passing the parent's end is what
 * makes a child that overruns its parent an error rather than a read into a
 * sibling, and it is the only bounds argument in the program, so there is one
 * place to get it right.
 *
 * Every DER restriction that a BER reader may ignore is enforced here rather
 * than at the call sites. A reader that is strict in some places and lax in
 * others is strict nowhere: the lax path is the one an attacker picks.
 */
static void hdr(const uint8_t *b, size_t end, size_t off, Hdr *h) {
	size_t i = off;
	if (i >= end) die("truncated at %zu: no identifier octet", off);
	unsigned id = b[i++];
	h->off = off;
	h->cls = id >> 6;
	h->cons = (id & 0x20) != 0;
	h->tag = id & 0x1f;

	if (h->tag == 0x1f) {
		/* X.690 8.1.2.4: tag numbers above 30 travel as base-128
		 * continuation bytes, high bit set on all but the last. The
		 * two degenerate forms are already illegal in BER: a leading
		 * 0x80 pads the number with a zero septet, and a number below
		 * 31 had a one-byte form available. */
		if (i < end && b[i] == 0x80) die("non-minimal tag number at %zu", off);
		uint64_t t = 0;
		for (;;) {
			if (i >= end) die("truncated tag number at %zu", off);
			if (t > (UINT64_MAX >> 7)) die("tag number too large at %zu", off);
			t = (t << 7) | (b[i] & 0x7fu);
			if (!(b[i++] & 0x80)) break;
		}
		if (t < 0x1f) die("non-minimal tag number at %zu", off);
		/* The printed form is "<ASN1 %u>" / "cont [ %u ]", so the tag
		 * has to fit the width we print it at; a 2^32 tag number is
		 * not a thing any real encoder emits. */
		if (t > 0xffffffffu) die("tag number too large at %zu", off);
		h->tag = (unsigned)t;
	}

	if (i >= end) die("truncated at %zu: no length octet", off);
	unsigned l0 = b[i++];
	size_t len;
	if (l0 < 0x80) {
		len = l0;
	} else if (l0 == 0x80) {
		/* X.690 10.1: DER is definite-length only. BER's indefinite
		 * form, terminated by an end-of-contents pair, means a reader
		 * cannot know where an element ends without parsing all of it
		 * -- which is exactly the property a length field exists to
		 * provide. openssl accepts it and prints "l=inf". We do not. */
		die("indefinite length at %zu: DER requires a definite length", off);
	} else if (l0 == 0xff) {
		die("reserved length octet 0xff at %zu", off);
	} else {
		unsigned k = l0 & 0x7fu;
		if (end - i < k) die("truncated length at %zu", off);
		if (b[i] == 0) die("non-minimal length at %zu: leading zero octet", off);
		/* The leading-zero check above means a k wider than a size_t
		 * really is a length no address space can hold, not just a
		 * padded small number. */
		if (k > sizeof(size_t)) die("length at %zu does not fit in size_t", off);
		len = 0;
		for (unsigned j = 0; j < k; j++) len = (len << 8) | b[i++];
		/* X.690 10.1 again: lengths under 128 must use the short
		 * form, so there is exactly one encoding of each length. */
		if (len < 0x80) die("non-minimal length at %zu: short form required", off);
	}
	h->hl = i - off;
	h->len = len;
	if (end - i < len)
		die("element at %zu claims %zu content bytes, %zu available",
		    off, len, end - i);
}

/* --------------------------------------------------------------- tag names */

/*
 * The names openssl's ASN1_tag2str prints, which are not all the names X.680
 * uses -- tag 26 is VisibleString in the standard and "VISIBLESTRING" here,
 * tag 20 is TeletexString and "T61STRING" here. These are the oracle's
 * spelling because the test is a diff against the oracle; t/run.sh feeds a
 * one-element file for every tag from 0 to 30 and asserts all 31 agree.
 */
static const char *univ_name[31] = {
	"EOC", "BOOLEAN", "INTEGER", "BIT STRING", "OCTET STRING", "NULL",
	"OBJECT", "OBJECT DESCRIPTOR", "EXTERNAL", "REAL", "ENUMERATED",
	"<ASN1 11>", "UTF8STRING", "<ASN1 13>", "<ASN1 14>", "<ASN1 15>",
	"SEQUENCE", "SET", "NUMERICSTRING", "PRINTABLESTRING", "T61STRING",
	"VIDEOTEXSTRING", "IA5STRING", "UTCTIME", "GENERALIZEDTIME",
	"GRAPHICSTRING", "VISIBLESTRING", "GENERALSTRING", "UNIVERSALSTRING",
	"<ASN1 29>", "BMPSTRING"
};

/* Returns a pointer into `scratch` for the forms that have to be formatted. */
static const char *tagname(const Hdr *h, char *scratch, size_t ns) {
	switch (h->cls) {
	case CLS_UNIV:
		if (h->tag <= 30) return univ_name[h->tag];
		snprintf(scratch, ns, "<ASN1 %u>", h->tag);
		return scratch;
	case CLS_APPL: snprintf(scratch, ns, "appl [ %u ]", h->tag); return scratch;
	case CLS_CONT: snprintf(scratch, ns, "cont [ %u ]", h->tag); return scratch;
	default:       snprintf(scratch, ns, "priv [ %u ]", h->tag); return scratch;
	}
}

/*
 * asn1parse's column layout, reproduced exactly, including the trailing
 * blanks on a line with no value. Deriving it from the output rather than
 * from openssl's source: offset %5, depth %-2 followed by a literal space,
 * length %4, then the depth as indentation (depth + 1 spaces), then the tag
 * name left-padded to 18. Anything off by one space here makes every later
 * comparison a diff of whitespace, so this is the one function the whole
 * oracle rests on.
 */
static void print_hdr(const Hdr *h, int depth) {
	char scratch[32];
	printf("%5zu:d=%-2d hl=%zu l=%4zu %s:%*s%-18s",
	       h->off, depth, h->hl, h->len, h->cons ? "cons" : "prim",
	       depth + 1, "", tagname(h, scratch, sizeof scratch));
}

/* ------------------------------------------------------------ values */

/*
 * Which universal tags asn1parse prints a value for, and in what shape. This
 * is not "which tags have printable content" -- BIT STRING and BMPSTRING both
 * have content and openssl prints neither -- it is a list openssl happens to
 * carry, so it is reproduced as a list and checked tag by tag against the
 * oracle rather than derived from a principle that does not exist.
 *
 * Note the ':' is unconditional for the string tags: a zero-length
 * PrintableString prints as ":" and nothing else.
 */
static int is_rawstring(unsigned tag) {
	switch (tag) {
	case 12: case 18: case 19: case 20: case 22: case 23: case 24: case 26:
		return 1;
	default:
		return 0;
	}
}

/* openssl's test, byte for byte: printable means every byte is in the range
 * ' ' to '~' inclusive, or is one of tab, newline or carriage return. 0x7f is
 * not printable because it is greater than '~'. */
static int octets_printable(const uint8_t *p, size_t n) {
	for (size_t i = 0; i < n; i++)
		if ((p[i] < ' ' && p[i] != '\n' && p[i] != '\r' && p[i] != '\t')
		    || p[i] > '~')
			return 0;
	return 1;
}

static void put_hex(const uint8_t *p, size_t n) {
	for (size_t i = 0; i < n; i++) printf("%02X", p[i]);
}

/*
 * INTEGER and ENUMERATED. openssl prints sign-and-magnitude -- "-81" for the
 * two bytes FF 7F -- because it has already decoded into an ASN1_INTEGER,
 * which stores the magnitude and the sign separately. So a negative value has
 * to be negated before it can be printed, and the negation is done without a
 * buffer: for the last nonzero byte take its two's complement, for every byte
 * before it take the ones' complement, and everything after it is zero. That
 * is exactly invert-and-add-one carried out in place.
 *
 * Leading zero *bytes* of the magnitude are dropped, but no further: openssl
 * prints -512 (FE 00) as "-0200", keeping the low zero byte, and FF 00 01 as
 * "-FFFF", dropping the high one.
 */
static void print_int(const uint8_t *p, size_t n) {
	if (n == 0) die("INTEGER of zero length");
	/* X.690 8.3.2: the first nine bits may not be all zero or all one, or
	 * the first octet is redundant. DER has one encoding per value and
	 * this is the rule that makes that true for integers; openssl accepts
	 * the redundant form and prints "BAD INTEGER". */
	if (n > 1 && ((p[0] == 0x00 && p[1] < 0x80) || (p[0] == 0xff && p[1] >= 0x80)))
		die("non-minimal INTEGER: redundant leading byte %02X", p[0]);

	if (!(p[0] & 0x80)) {
		size_t s = (n > 1 && p[0] == 0) ? 1 : 0;
		put_hex(p + s, n - s);
		return;
	}
	size_t k = n - 1;                      /* last nonzero byte */
	while (k > 0 && p[k] == 0) k--;
	size_t s = 0;                          /* first nonzero magnitude byte */
	while (s < k && p[s] == 0xff) s++;
	putchar('-');
	for (size_t i = s; i < n; i++) {
		unsigned v = i > k ? 0u
		           : i == k ? (0x100u - p[i]) & 0xffu
		           : (unsigned)(uint8_t)~p[i];
		printf("%02X", v);
	}
}

static void print_value(const uint8_t *b, const Hdr *h) {
	const uint8_t *p = b + h->off + h->hl;
	size_t n = h->len;
	if (h->cls != CLS_UNIV) return;  /* openssl prints no value for these */

	switch (h->tag) {
	case 1:
		/* X.690 11.1: DER encodes TRUE as a single 0xff octet, so
		 * there is one encoding of each truth value. openssl prints
		 * "BAD BOOLEAN" for anything else and carries on; a BOOLEAN
		 * that is neither 0x00 nor 0xff is an encoder that is not
		 * emitting DER, and nothing good is downstream of that. */
		if (n != 1) die("BOOLEAN of length %zu, must be 1", n);
		if (p[0] != 0x00 && p[0] != 0xff)
			die("non-DER BOOLEAN %02X, must be 00 or FF", p[0]);
		printf(":%u", p[0]);
		return;
	case 2: case 10:
		putchar(':');
		print_int(p, n);
		return;
	case 4:
		/* An octet string holds bytes, and openssl guesses: if they
		 * all look like text it shows them as text, otherwise as hex
		 * behind a "[HEX DUMP]:" marker. Empty prints nothing at all,
		 * not even the colon -- unlike the string tags. */
		if (n == 0) return;
		if (octets_printable(p, n)) {
			putchar(':');
			fwrite(p, 1, n, stdout);
		} else {
			fputs("[HEX DUMP]:", stdout);
			put_hex(p, n);
		}
		return;
	default:
		if (is_rawstring(h->tag)) {
			putchar(':');
			fwrite(p, 1, n, stdout);
		}
		return;
	}
}

/* ----------------------------------------------------------------- parse */

/*
 * 128 is openssl's ASN1_PARSE_MAXDEPTH, confirmed by experiment rather than
 * assumed: a chain of N nested SEQUENCEs is accepted by asn1parse up to and
 * including a printed depth of 128 and prints "BAD RECURSION DEPTH" with exit
 * 1 at 129. Matching the number exactly keeps the accept/reject boundary the
 * oracle's rather than ours, and a limit has to exist regardless -- walk()
 * recurses, each level of nesting costs two input bytes, and a 1MB file of
 * "\x30\x02" repeated would otherwise be a stack overflow instead of a
 * diagnostic.
 */
#define MAXDEPTH 128

static void walk(const uint8_t *b, size_t beg, size_t end, int depth) {
	size_t i = beg;
	/* A file may hold several top-level elements, and a constructed
	 * element holds a run of them; openssl walks both the same way and
	 * errors if the last one is short, so one loop serves both. */
	while (i < end) {
		Hdr h;
		hdr(b, end, i, &h);
		print_hdr(&h, depth);
		if (!h.cons) print_value(b, &h);
		putchar('\n');
		if (h.cons) {
			if (depth >= MAXDEPTH)
				die("nesting deeper than %d at offset %zu",
				    MAXDEPTH, h.off);
			walk(b, h.off + h.hl, h.off + h.hl + h.len, depth + 1);
		}
		i = h.off + h.hl + h.len;
	}
}

static void cmd_parse(const uint8_t *b, size_t n) { walk(b, 0, n, 0); }

/* ------------------------------------------------------------------- main */

static void usage(void) {
	fputs("usage: derx parse FILE | derx cert FILE   (FILE of - is stdin)\n",
	      stderr);
	exit(2);
}

int main(int argc, char **argv) {
	if (argc != 3) usage();
	size_t n;
	uint8_t *b = slurp(argv[2], &n);
	if (strcmp(argv[1], "parse") == 0) cmd_parse(b, n);
	else usage();
	if (fflush(stdout) != 0) die("write error");
	free(b);
	return 0;
}
