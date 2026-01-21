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
	/*
	 * X.690 10.2: where a type's value is primitive, DER requires the
	 * primitive form. BER's alternative is a constructed string, split
	 * into segments -- so "hello" can travel as one OCTET STRING or as
	 * five, and a reader that accepts both has two encodings for one
	 * value, which is the exact property DER exists to remove. The three
	 * universal tags that are SEQUENCE types go the other way and may
	 * only be constructed.
	 *
	 * Tags 11, 13, 14, 15 and 29 are classified neither way on purpose:
	 * openssl has no name for them, so the oracle has no opinion about
	 * them and neither do we.
	 */
	if (h->cls == CLS_UNIV && h->tag <= 30) {
		static const uint32_t prim_only =
			(1u << 1) | (1u << 2) | (1u << 3) | (1u << 4) |
			(1u << 5) | (1u << 6) | (1u << 7) | (1u << 9) |
			(1u << 10) | (1u << 12) | (1u << 18) | (1u << 19) |
			(1u << 20) | (1u << 21) | (1u << 22) | (1u << 23) |
			(1u << 24) | (1u << 25) | (1u << 26) | (1u << 27) |
			(1u << 28) | (1u << 30);
		static const uint32_t cons_only =
			(1u << 8) | (1u << 16) | (1u << 17);
		uint32_t bit = 1u << h->tag;
		if (h->cons && (prim_only & bit))
			die("constructed universal tag %u at %zu: DER requires "
			    "the primitive form", h->tag, off);
		if (!h->cons && (cons_only & bit))
			die("primitive universal tag %u at %zu: DER requires "
			    "the constructed form", h->tag, off);
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

/* -------------------------------------------------------------------- OIDs */

/*
 * The names openssl prints for the OIDs this project meets. Three columns:
 * the dotted form, the long name asn1parse prints for an OBJECT, and the
 * name X509_NAME_print_ex prints for a relative distinguished name under
 * -nameopt RFC2253, which is openssl's short name where it has one and the
 * long name where it does not.
 *
 * This table is data I typed, which makes it the weakest thing in the
 * program -- so it is also the most thoroughly checked. Every entry is
 * verified by diff: get a dotted value wrong and derx prints digits where
 * asn1parse prints a name, which fails on the first certificate that carries
 * it. The RDN column is verified the same way against `openssl x509 -nameopt
 * RFC2253 -subject`. The rows came from asking openssl, not from memory: a
 * certificate was generated carrying all 24 attribute types and the names
 * read back out of its own output.
 *
 * An OID absent from the table prints in dotted form, which is also what
 * openssl does for an OID it does not know -- so the two agree there as well,
 * and 1.3.6.1.4.1.311.21.1 in the corpus is a live example of that path.
 * The failure that cannot happen silently is an OID openssl names and we do
 * not: that is a diff, every time, on every certificate containing it.
 */
static const struct { const char *dotted, *ln, *rdn; } oidtab[] = {
	/* X.520 attribute types, in the order openssl printed them back */
	{ "2.5.4.3",  "commonName",             "CN" },
	{ "2.5.4.10", "organizationName",       "O" },
	{ "2.5.4.11", "organizationalUnitName", "OU" },
	{ "2.5.4.6",  "countryName",            "C" },
	{ "2.5.4.7",  "localityName",           "L" },
	{ "2.5.4.8",  "stateOrProvinceName",    "ST" },
	{ "2.5.4.9",  "streetAddress",          "street" },
	{ "2.5.4.17", "postalCode",             "postalCode" },
	{ "2.5.4.12", "title",                  "title" },
	{ "2.5.4.4",  "surname",                "SN" },
	{ "2.5.4.42", "givenName",              "GN" },
	{ "2.5.4.43", "initials",               "initials" },
	{ "2.5.4.15", "businessCategory",       "businessCategory" },
	{ "2.5.4.5",  "serialNumber",           "serialNumber" },
	{ "2.5.4.46", "dnQualifier",            "dnQualifier" },
	{ "2.5.4.65", "pseudonym",              "pseudonym" },
	{ "2.5.4.97", "organizationIdentifier", "organizationIdentifier" },
	{ "2.5.4.13", "description",            "description" },
	{ "2.5.4.41", "name",                   "name" },
	{ "2.5.4.44", "generationQualifier",    "generationQualifier" },
	{ "2.5.4.45", "x500UniqueIdentifier",   "x500UniqueIdentifier" },
	{ "1.2.840.113549.1.9.1",        "emailAddress",    "emailAddress" },
	{ "0.9.2342.19200300.100.1.25",  "domainComponent", "DC" },
	{ "0.9.2342.19200300.100.1.1",   "userId",          "UID" },

	/* algorithms */
	{ "1.2.840.113549.1.1.1",  "rsaEncryption",           NULL },
	{ "1.2.840.113549.1.1.5",  "sha1WithRSAEncryption",   NULL },
	{ "1.2.840.113549.1.1.10", "rsassaPss",               NULL },
	{ "1.2.840.113549.1.1.11", "sha256WithRSAEncryption", NULL },
	{ "1.2.840.113549.1.1.12", "sha384WithRSAEncryption", NULL },
	{ "1.2.840.113549.1.1.13", "sha512WithRSAEncryption", NULL },
	{ "1.2.840.10045.2.1",     "id-ecPublicKey",          NULL },
	{ "1.2.840.10045.4.1",     "ecdsa-with-SHA1",         NULL },
	{ "1.2.840.10045.4.3.2",   "ecdsa-with-SHA256",       NULL },
	{ "1.2.840.10045.4.3.3",   "ecdsa-with-SHA384",       NULL },
	{ "1.2.840.10045.4.3.4",   "ecdsa-with-SHA512",       NULL },
	{ "1.2.840.10045.3.1.7",   "prime256v1",              NULL },
	{ "1.3.132.0.34",          "secp384r1",               NULL },
	{ "1.3.132.0.35",          "secp521r1",               NULL },
	{ "1.3.101.112",           "ED25519",                 NULL },
	{ "1.3.101.113",           "ED448",                   NULL },
	{ "2.16.840.1.101.3.4.2.1", "sha256",                 NULL },
	{ "2.16.840.1.101.3.4.2.2", "sha384",                 NULL },
	{ "2.16.840.1.101.3.4.2.3", "sha512",                 NULL },

	/* certificate extensions */
	{ "2.5.29.9",  "X509v3 Subject Directory Attributes", NULL },
	{ "2.5.29.14", "X509v3 Subject Key Identifier",       NULL },
	{ "2.5.29.15", "X509v3 Key Usage",                    NULL },
	{ "2.5.29.16", "X509v3 Private Key Usage Period",     NULL },
	{ "2.5.29.17", "X509v3 Subject Alternative Name",     NULL },
	{ "2.5.29.18", "X509v3 Issuer Alternative Name",      NULL },
	{ "2.5.29.19", "X509v3 Basic Constraints",            NULL },
	{ "2.5.29.30", "X509v3 Name Constraints",             NULL },
	{ "2.5.29.31", "X509v3 CRL Distribution Points",      NULL },
	{ "2.5.29.32", "X509v3 Certificate Policies",         NULL },
	{ "2.5.29.33", "X509v3 Policy Mappings",              NULL },
	{ "2.5.29.35", "X509v3 Authority Key Identifier",     NULL },
	{ "2.5.29.36", "X509v3 Policy Constraints",           NULL },
	{ "2.5.29.37", "X509v3 Extended Key Usage",           NULL },
	{ "2.5.29.46", "X509v3 Freshest CRL",                 NULL },
	{ "2.5.29.54", "X509v3 Inhibit Any Policy",           NULL },
	{ "1.3.6.1.5.5.7.1.1", "Authority Information Access", NULL },

	/* extended key usage purposes, used by `derx cert` */
	{ "1.3.6.1.5.5.7.3.1", "TLS Web Server Authentication", NULL },
	{ "1.3.6.1.5.5.7.3.2", "TLS Web Client Authentication", NULL },
	{ "1.3.6.1.5.5.7.3.3", "Code Signing",                  NULL },
	{ "1.3.6.1.5.5.7.3.4", "E-mail Protection",             NULL },
	{ "1.3.6.1.5.5.7.3.8", "Time Stamping",                 NULL },
	{ "1.3.6.1.5.5.7.3.9", "OCSP Signing",                  NULL },
	{ "2.5.29.37.0",       "Any Extended Key Usage",        NULL },

	{ "2.16.840.1.113730.1.1", "Netscape Cert Type",      NULL },
	{ "2.23.42.7.0",       "setCext-hashedRoot",          NULL },
};
#define NOID ((int)(sizeof oidtab / sizeof *oidtab))

static const char *oid_ln(const char *dotted) {
	for (int i = 0; i < NOID; i++)
		if (strcmp(oidtab[i].dotted, dotted) == 0) return oidtab[i].ln;
	return NULL;
}

/* openssl's short name where it has one, long name where it does not, NULL
 * for an OID that is not an attribute type we know. */
static const char *oid_rdn(const char *dotted) {
	for (int i = 0; i < NOID; i++)
		if (strcmp(oidtab[i].dotted, dotted) == 0) return oidtab[i].rdn;
	return NULL;
}

/* shortcut: one fixed buffer for the dotted text and 128 decimal digits per
 * arc, so an arc above about 2^425 or an OID beyond 127 arcs is refused by
 * name instead of printed. openssl needs a BIGNUM to print either and no
 * registry contains one; the upgrade path is a growable digit array and a
 * growable output buffer, which is the same loop with realloc in it. */
#define OIDTEXTMAX 512
#define OIDARCDIGITS 128

static void oid_append(char *out, size_t *len, const char *s) {
	size_t n = strlen(s);
	if (*len + n + 1 > OIDTEXTMAX) die("OID longer than %d characters", OIDTEXTMAX);
	memcpy(out + *len, s, n + 1);
	*len += n;
}

/*
 * Decode the content of an OBJECT IDENTIFIER into dotted decimal.
 *
 * X.690 8.19: the arcs are base-128 with the high bit set on every byte but
 * the last of each arc, and the first two arcs are packed into one number as
 * 40*X + Y. The unpacking has a wart worth naming: X is capped at 2, so arc
 * values of 80 and above all belong to X=2 and Y runs past 39 -- which is why
 * 2.999 is a legal OID and encodes as the single arc 1079.
 *
 * Arcs are accumulated as decimal digits rather than into a uint64, because
 * openssl prints arbitrarily wide arcs (it reaches for a BIGNUM) and
 * 1.2.2361183241434822606848 is a legal OID that a 64-bit accumulator turns
 * into a wrong answer rather than an error. Only the first arc goes through a
 * uint64, because unpacking 40*X + Y needs arithmetic and an arc that wide in
 * the first position does not exist.
 */
static void oid_text(const uint8_t *p, size_t n, char *out, size_t *outlen) {
	if (n == 0) die("OBJECT IDENTIFIER of zero length");
	if (p[n - 1] & 0x80) die("OBJECT IDENTIFIER ends mid-arc");
	*outlen = 0;
	out[0] = '\0';

	size_t i = 0;
	int first = 1;
	while (i < n) {
		size_t beg = i;
		/* X.690 8.19.2: an arc's leading byte may not be 0x80, which
		 * would pad the value with a zero septet. openssl rejects
		 * this too, printing "BAD OBJECT". */
		if (p[beg] == 0x80) die("non-minimal OID arc at content byte %zu", beg);
		while (p[i] & 0x80) i++;   /* the final byte above guarantees a stop */
		i++;

		char buf[OIDARCDIGITS + 24];
		if (first) {
			uint64_t v = 0;
			for (size_t j = beg; j < i; j++) {
				if (v > (UINT64_MAX >> 7))
					die("first OID arc wider than 64 bits");
				v = (v << 7) | (p[j] & 0x7fu);
			}
			unsigned long x = v < 80 ? (unsigned long)(v / 40) : 2;
			snprintf(buf, sizeof buf, "%lu.%llu", x,
			         (unsigned long long)(v - 40 * x));
			oid_append(out, outlen, buf);
			first = 0;
			continue;
		}
		/* Decimal long multiplication: value = value*128 + septet,
		 * least significant digit first so a carry just extends the
		 * array. */
		unsigned char d[OIDARCDIGITS];
		size_t nd = 1;
		d[0] = 0;
		for (size_t j = beg; j < i; j++) {
			unsigned carry = p[j] & 0x7fu;
			for (size_t k = 0; k < nd; k++) {
				unsigned v = d[k] * 128u + carry;
				d[k] = (unsigned char)(v % 10);
				carry = v / 10;
			}
			while (carry) {
				if (nd == sizeof d)
					die("OID arc wider than %d decimal digits",
					    OIDARCDIGITS);
				d[nd++] = (unsigned char)(carry % 10);
				carry /= 10;
			}
		}
		buf[0] = '.';
		size_t w = 1;
		for (size_t k = nd; k-- > 0;) buf[w++] = (char)('0' + d[k]);
		buf[w] = '\0';
		oid_append(out, outlen, buf);
	}
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
	case 6: {
		char txt[OIDTEXTMAX];
		size_t len;
		oid_text(p, n, txt, &len);
		const char *ln = oid_ln(txt);
		printf(":%s", ln ? ln : txt);
		return;
	}
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

static void cmd_parse(const uint8_t *b, size_t n) {
	/* Nothing is not a DER element. openssl says "offset out of range"
	 * and exits 1 here, and an empty file silently succeeding is how a
	 * suite ends up asserting against no output at all. */
	if (n == 0) die("empty input: no DER element");
	walk(b, 0, n, 0);
}

/* ======================================================== X.509 (RFC 5280) */

/*
 * A cursor over one element's content. Everything below walks the certificate
 * with these three calls and never indexes the buffer directly, so the bound
 * that hdr() enforces -- the end of the enclosing element -- is the only
 * bound there is.
 */
typedef struct { const uint8_t *b; size_t i, end; } Rd;

static int rd_more(const Rd *r) { return r->i < r->end; }

static Hdr rd_peek(const Rd *r, const char *what) {
	if (!rd_more(r)) die("%s: expected another element, found none", what);
	Hdr h;
	hdr(r->b, r->end, r->i, &h);
	return h;
}
static Hdr rd_next(Rd *r, const char *what) {
	Hdr h = rd_peek(r, what);
	r->i = h.off + h.hl + h.len;
	return h;
}
static Rd rd_in(const Rd *r, const Hdr *h) {
	Rd s;
	s.b = r->b;
	s.i = h->off + h->hl;
	s.end = s.i + h->len;
	return s;
}
static void rd_end(const Rd *r, const char *what) {
	if (rd_more(r)) die("%s: %zu unexpected trailing bytes at %zu",
	                    what, r->end - r->i, r->i);
}
static const uint8_t *content(const Hdr *h, const uint8_t *b) {
	return b + h->off + h->hl;
}

static void expect(const Hdr *h, unsigned cls, unsigned tag, int cons,
                   const char *what) {
	if (h->cls != cls || h->tag != tag || h->cons != cons)
		die("%s: expected class %u tag %u %s at %zu, found class %u "
		    "tag %u %s", what, cls, tag, cons ? "constructed" : "primitive",
		    h->off, h->cls, h->tag, h->cons ? "constructed" : "primitive");
}

/* A small non-negative INTEGER: version numbers, path lengths. */
static unsigned long small_int(const Hdr *h, const uint8_t *b) {
	expect(h, CLS_UNIV, 2, 0, "integer");
	const uint8_t *p = content(h, b);
	if (h->len == 0) die("INTEGER of zero length");
	if (p[0] & 0x80) die("negative INTEGER where a count was expected");
	if (h->len > 5 || (h->len == 5 && p[0] != 0))
		die("INTEGER too large for a count at %zu", h->off);
	unsigned long v = 0;
	for (size_t i = 0; i < h->len; i++) v = (v << 8) | p[i];
	return v;
}

/* The dotted form of an OBJECT, into caller-supplied storage. */
static const char *oid_of(const Hdr *h, const uint8_t *b, char *txt) {
	expect(h, CLS_UNIV, 6, 0, "object identifier");
	size_t len;
	oid_text(content(h, b), h->len, txt, &len);
	return txt;
}

/* ------------------------------------------------------------ directory strings */

/*
 * One character of a directory string as a Unicode code point, advancing *i.
 *
 * openssl converts every string type to UTF-8 before escaping it, and what it
 * converts *with* is worth naming because it is not what the standards say:
 * the one-byte-per-character types all go through MBSTRING_ASC, which treats
 * each byte as a code point. So a T61String byte 0xC1 becomes U+00C1, Latin-1
 * capital A with acute, and not T.61's combining acute accent. Checked against
 * the oracle with a hand-built certificate, because openssl's own generator
 * will not emit one. See t/run.sh.
 */
static unsigned long str_cp(const uint8_t *p, size_t n, size_t *i, unsigned tag) {
	size_t k = *i;
	unsigned long c;
	switch (tag) {
	case 30: /* BMPString: UCS-2, big endian */
		if (n - k < 2) die("BMPString of odd length");
		*i = k + 2;
		c = ((unsigned long)p[k] << 8) | p[k + 1];
		if (c >= 0xd800 && c <= 0xdfff)
			die("BMPString containing a UTF-16 surrogate");
		return c;
	case 28: /* UniversalString: UCS-4, big endian */
		if (n - k < 4) die("UniversalString length is not a multiple of 4");
		*i = k + 4;
		c = ((unsigned long)p[k] << 24) | ((unsigned long)p[k + 1] << 16)
		  | ((unsigned long)p[k + 2] << 8) | p[k + 3];
		if (c > 0x10ffff || (c >= 0xd800 && c <= 0xdfff))
			die("UniversalString code point U+%lX is not a character", c);
		return c;
	case 12: { /* UTF8String: decoded and re-encoded, so it must be valid */
		unsigned need;
		unsigned long lo;
		if (p[k] < 0x80)                      { *i = k + 1; return p[k]; }
		else if ((p[k] & 0xe0) == 0xc0) { need = 1; c = p[k] & 0x1fu; lo = 0x80; }
		else if ((p[k] & 0xf0) == 0xe0) { need = 2; c = p[k] & 0x0fu; lo = 0x800; }
		else if ((p[k] & 0xf8) == 0xf0) { need = 3; c = p[k] & 0x07u; lo = 0x10000; }
		else die("UTF8String: byte %02X is not the start of a character", p[k]);
		if (n - k < need + 1) die("UTF8String: truncated character");
		for (unsigned j = 1; j <= need; j++) {
			if ((p[k + j] & 0xc0) != 0x80)
				die("UTF8String: byte %02X is not a continuation", p[k + j]);
			c = (c << 6) | (p[k + j] & 0x3fu);
		}
		/* An overlong encoding is a second spelling of a character
		 * that already has one, and historically the way past a filter
		 * that only checked the short spelling. openssl's decoder
		 * refuses these and so does the whole certificate. */
		if (c < lo) die("UTF8String: overlong encoding of U+%lX", c);
		if (c > 0x10ffff || (c >= 0xd800 && c <= 0xdfff))
			die("UTF8String: U+%lX is not a character", c);
		*i = k + need + 1;
		return c;
	}
	default: /* PrintableString, T61String, IA5String, NumericString */
		*i = k + 1;
		return p[k];
	}
}

static int renderable_string(unsigned tag) {
	switch (tag) {
	case 12: case 18: case 19: case 20: case 22: case 28: case 30: return 1;
	default: return 0;
	}
}

/*
 * RFC 2253 section 2.4 escaping, as openssl implements it under
 * -nameopt RFC2253. Every rule here was read off the oracle's output rather
 * than off the RFC, because the two do not quite agree and the oracle is what
 * the test compares against:
 *
 *   , + " \ < > ;       always backslash-escaped
 *   # and space         backslash-escaped only as the first character
 *   space               backslash-escaped as the last character
 *   below 0x20, or 0x7F escaped as \XX, uppercase, two digits
 *   above 0x7F          the UTF-8 bytes, each as \XX
 *
 * and nothing else: =, *, /, and a non-leading # all travel unescaped.
 */
static void put_dstring(const uint8_t *p, size_t n, unsigned tag) {
	size_t i = 0, idx = 0;
	while (i < n) {
		unsigned long c = str_cp(p, n, &i, tag);
		int first = idx++ == 0, last = i == n;
		if (c >= 0x80) {
			uint8_t u[4];
			size_t w;
			if (c < 0x800) {
				u[0] = (uint8_t)(0xc0 | (c >> 6));
				u[1] = (uint8_t)(0x80 | (c & 0x3f));
				w = 2;
			} else if (c < 0x10000) {
				u[0] = (uint8_t)(0xe0 | (c >> 12));
				u[1] = (uint8_t)(0x80 | ((c >> 6) & 0x3f));
				u[2] = (uint8_t)(0x80 | (c & 0x3f));
				w = 3;
			} else {
				u[0] = (uint8_t)(0xf0 | (c >> 18));
				u[1] = (uint8_t)(0x80 | ((c >> 12) & 0x3f));
				u[2] = (uint8_t)(0x80 | ((c >> 6) & 0x3f));
				u[3] = (uint8_t)(0x80 | (c & 0x3f));
				w = 4;
			}
			for (size_t j = 0; j < w; j++) printf("\\%02X", u[j]);
			continue;
		}
		int ch = (int)c;
		if (ch < 0x20 || ch == 0x7f) { printf("\\%02X", ch); continue; }
		if (strchr(",+\"\\<>;", ch) != NULL
		    || (first && (ch == '#' || ch == ' '))
		    || (last && ch == ' '))
			putchar('\\');
		putchar(ch);
	}
}

/* ---------------------------------------------------------------- names */

/* shortcut: a flat array, so a distinguished name with more than 256
 * attributes is refused by name rather than printed. RFC 5280 puts no bound
 * on it; the certificates on this machine use at most five. Growing it means
 * a realloc, or two passes over the same bytes to count first. */
#define MAXATV 256
typedef struct { int set; Hdr type, val; } Atv;

/*
 * Name ::= RDNSequence ::= SEQUENCE OF SET OF AttributeTypeAndValue.
 *
 * Printed the way -nameopt RFC2253 prints it, which is reverse order
 * throughout: the attributes are flattened in encoding order and then emitted
 * back to front, joined by "+" while they stay inside one SET and by ","
 * when the SET changes. So a subject encoded C, O, CN prints as CN=...,O=...,
 * C=..., and a two-attribute SET encoded CN then O prints as O=b+CN=a.
 *
 * An attribute type the table does not know prints as the dotted OID with
 * the value dumped as "#" plus the hex of the whole DER element, header
 * included -- openssl's XN_FLAG_DUMP_UNKNOWN_FIELDS. The same dump is used
 * for a known type whose value is not one of the seven string types openssl
 * will convert.
 */
static void print_name(const Rd *outer, const Hdr *nh, const char *what) {
	Atv a[MAXATV];
	int na = 0, set = 0;
	Rd seqr = rd_in(outer, nh);
	expect(nh, CLS_UNIV, 16, 1, what);
	while (rd_more(&seqr)) {
		Hdr rdn = rd_next(&seqr, what);
		expect(&rdn, CLS_UNIV, 17, 1, "relative distinguished name");
		Rd setr = rd_in(&seqr, &rdn);
		if (!rd_more(&setr)) die("%s: empty relative distinguished name", what);
		while (rd_more(&setr)) {
			Hdr atv = rd_next(&setr, "attribute");
			expect(&atv, CLS_UNIV, 16, 1, "attribute");
			Rd ar = rd_in(&setr, &atv);
			if (na == MAXATV) die("%s: more than %d attributes", what, MAXATV);
			a[na].set = set;
			a[na].type = rd_next(&ar, "attribute type");
			a[na].val = rd_next(&ar, "attribute value");
			rd_end(&ar, "attribute");
			na++;
		}
		set++;
	}
	if (na == 0) die("%s: empty name", what);

	for (int i = na - 1; i >= 0; i--) {
		char txt[OIDTEXTMAX];
		const char *dotted = oid_of(&a[i].type, outer->b, txt);
		const char *sn = oid_rdn(dotted);
		const Hdr *v = &a[i].val;
		/* openssl's X509_NAME template accepts a handful of value
		 * types beyond the string ones -- BIT STRING and SEQUENCE are
		 * in its ASN1_PRINTABLE mask -- and refuses the rest outright,
		 * declining to build a name at all. derx takes the narrower
		 * line and refuses anything it cannot render as text, so the
		 * only values it dumps as hex are string values under an
		 * attribute type it has no name for. */
		if (v->cls != CLS_UNIV || v->cons || !renderable_string(v->tag))
			die("%s: attribute value at %zu is not a string type "
			    "derx renders", what, v->off);
		if (sn != NULL) {
			printf("%s=", sn);
			put_dstring(content(v, outer->b), v->len, v->tag);
		} else {
			printf("%s=#", dotted);
			put_hex(outer->b + v->off, v->hl + v->len);
		}
		if (i > 0) putchar(a[i - 1].set == a[i].set ? '+' : ',');
	}
}

/* ----------------------------------------------------------------- time */

/*
 * UTCTime is YYMMDDHHMMSSZ and GeneralizedTime is YYYYMMDDHHMMSSZ. RFC 5280
 * 4.1.2.5 requires exactly those two forms -- seconds present, always Zulu --
 * and forbids the fractional-second and offset variants that X.680 allows, so
 * anything else is refused rather than guessed at.
 *
 * The two-digit year rule is also RFC 5280's, not X.680's: 50 and above is
 * 19xx, below 50 is 20xx. Printed in openssl's ASN1_TIME_print layout, where
 * the day is right-aligned in two columns -- "Oct  9", two spaces.
 */
static void print_time(const Hdr *h, const uint8_t *b, const char *what) {
	static const char *mon[12] = { "Jan", "Feb", "Mar", "Apr", "May", "Jun",
		"Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };
	const uint8_t *p = content(h, b);
	size_t ndigit;
	int year;
	if (h->cls == CLS_UNIV && h->tag == 23 && h->len == 13) {
		ndigit = 12;
		year = -1;
	} else if (h->cls == CLS_UNIV && h->tag == 24 && h->len == 15) {
		ndigit = 14;
		year = 0;
	} else {
		die("%s: expected a 13-byte UTCTime or a 15-byte GeneralizedTime "
		    "at %zu", what, h->off);
		return;
	}
	for (size_t i = 0; i < ndigit; i++)
		if (p[i] < '0' || p[i] > '9')
			die("%s: non-digit in the timestamp at %zu", what, h->off);
	if (p[ndigit] != 'Z')
		die("%s: timestamp is not UTC (no trailing Z) at %zu", what, h->off);
	int d[14];
	for (size_t i = 0; i < ndigit; i++) d[i] = p[i] - '0';
	size_t o;
	if (year < 0) {
		year = d[0] * 10 + d[1];
		year += year >= 50 ? 1900 : 2000;
		o = 2;
	} else {
		year = d[0] * 1000 + d[1] * 100 + d[2] * 10 + d[3];
		o = 4;
	}
	int mo = d[o] * 10 + d[o + 1];
	int da = d[o + 2] * 10 + d[o + 3];
	int hh = d[o + 4] * 10 + d[o + 5];
	int mi = d[o + 6] * 10 + d[o + 7];
	int ss = d[o + 8] * 10 + d[o + 9];
	if (mo < 1 || mo > 12 || da < 1 || da > 31 || hh > 23 || mi > 59 || ss > 60)
		die("%s: timestamp is not a date at %zu", what, h->off);
	printf("%s %2d %02d:%02d:%02d %d GMT", mon[mo - 1], da, hh, mi, ss, year);
}

/* ------------------------------------------------------------ public key */

/* Bit length of a positive INTEGER's magnitude, which is what openssl means
 * by "Public-Key: (2048 bit)" for RSA. The leading 0x00 that keeps a modulus
 * positive is not part of the magnitude. */
static unsigned long int_bits(const Hdr *h, const uint8_t *b) {
	const uint8_t *p = content(h, b);
	size_t n = h->len, s = 0;
	while (s < n && p[s] == 0) s++;
	if (s == n) return 0;
	unsigned long bits = (unsigned long)(n - s - 1) * 8;
	unsigned top = p[s];
	while (top) { bits++; top >>= 1; }
	return bits;
}

static const struct { const char *oid; unsigned bits; } curvebits[] = {
	{ "1.2.840.10045.3.1.7", 256 },  /* prime256v1 */
	{ "1.3.132.0.34",        384 },  /* secp384r1 */
	{ "1.3.132.0.35",        521 },  /* secp521r1 */
};

/* ------------------------------------------------------------ extensions */

static void put_colon_hex(const uint8_t *p, size_t n) {
	for (size_t i = 0; i < n; i++) printf("%s%02X", i ? ":" : "", p[i]);
}

static const char *ku_name[9] = { "Digital Signature", "Non Repudiation",
	"Key Encipherment", "Data Encipherment", "Key Agreement",
	"Certificate Sign", "CRL Sign", "Encipher Only", "Decipher Only" };

/* Returns 0 if this extension is one derx does not decode, in which case
 * nothing was printed. */
static int print_ext_value(const char *dotted, const Rd *r, const Hdr *oct) {
	const uint8_t *b = r->b;
	Rd v = rd_in(r, oct);

	if (strcmp(dotted, "2.5.29.19") == 0) {        /* Basic Constraints */
		Hdr s = rd_next(&v, "basicConstraints");
		expect(&s, CLS_UNIV, 16, 1, "basicConstraints");
		rd_end(&v, "basicConstraints");
		Rd i = rd_in(&v, &s);
		int ca = 0;
		unsigned long plen = 0;
		int has_plen = 0;
		if (rd_more(&i)) {
			Hdr h = rd_peek(&i, "basicConstraints");
			if (h.cls == CLS_UNIV && h.tag == 1) {
				rd_next(&i, "cA");
				if (h.len != 1) die("cA is not one byte");
				ca = content(&h, b)[0] != 0;
			}
		}
		if (rd_more(&i)) {
			Hdr h = rd_next(&i, "pathLenConstraint");
			plen = small_int(&h, b);
			has_plen = 1;
		}
		rd_end(&i, "basicConstraints");
		printf("CA:%s", ca ? "TRUE" : "FALSE");
		if (has_plen) printf(", pathlen:%lu", plen);
		return 1;
	}
	if (strcmp(dotted, "2.5.29.15") == 0) {        /* Key Usage */
		Hdr s = rd_next(&v, "keyUsage");
		expect(&s, CLS_UNIV, 3, 0, "keyUsage");
		rd_end(&v, "keyUsage");
		if (s.len == 0) die("keyUsage BIT STRING has no unused-bits octet");
		const uint8_t *p = content(&s, b);
		unsigned unused = p[0];
		if (unused > 7) die("keyUsage declares %u unused bits", unused);
		size_t nbit = (s.len - 1) * 8 - unused;
		int printed = 0;
		for (size_t i = 0; i < nbit && i < 9; i++)
			if (p[1 + i / 8] & (0x80u >> (i % 8))) {
				printf("%s%s", printed ? ", " : "", ku_name[i]);
				printed = 1;
			}
		return 1;
	}
	if (strcmp(dotted, "2.5.29.37") == 0) {        /* Extended Key Usage */
		Hdr s = rd_next(&v, "extendedKeyUsage");
		expect(&s, CLS_UNIV, 16, 1, "extendedKeyUsage");
		rd_end(&v, "extendedKeyUsage");
		Rd i = rd_in(&v, &s);
		int printed = 0;
		while (rd_more(&i)) {
			Hdr h = rd_next(&i, "key purpose");
			char txt[OIDTEXTMAX];
			const char *d = oid_of(&h, b, txt);
			const char *ln = oid_ln(d);
			printf("%s%s", printed ? ", " : "", ln ? ln : d);
			printed = 1;
		}
		return 1;
	}
	if (strcmp(dotted, "2.5.29.14") == 0) {        /* Subject Key Identifier */
		Hdr s = rd_next(&v, "subjectKeyIdentifier");
		expect(&s, CLS_UNIV, 4, 0, "subjectKeyIdentifier");
		rd_end(&v, "subjectKeyIdentifier");
		put_colon_hex(content(&s, b), s.len);
		return 1;
	}
	if (strcmp(dotted, "2.5.29.35") == 0) {        /* Authority Key Identifier */
		Hdr s = rd_next(&v, "authorityKeyIdentifier");
		expect(&s, CLS_UNIV, 16, 1, "authorityKeyIdentifier");
		rd_end(&v, "authorityKeyIdentifier");
		Rd i = rd_in(&v, &s);
		if (!rd_more(&i)) return 0;
		Hdr h = rd_next(&i, "keyIdentifier");
		/* Only the keyIdentifier-alone form, which is what openssl
		 * prints as bare hex. With an authorityCertIssuer or serial
		 * present openssl prints three labelled lines instead, and
		 * this one-line-per-extension format has nowhere to put them;
		 * 5 of the 150 certificates on this machine are that shape. */
		if (rd_more(&i) || h.cls != CLS_CONT || h.tag != 0 || h.cons) return 0;
		put_colon_hex(content(&h, b), h.len);
		return 1;
	}
	if (strcmp(dotted, "2.5.29.17") == 0) {        /* Subject Alternative Name */
		Hdr s = rd_next(&v, "subjectAltName");
		expect(&s, CLS_UNIV, 16, 1, "subjectAltName");
		rd_end(&v, "subjectAltName");
		Rd i = rd_in(&v, &s);
		/* One unsupported GeneralName kind makes the whole value
		 * undecoded rather than a partial list, because a partial list
		 * of the names a certificate is valid for is worse than none. */
		Rd scan = i;
		while (rd_more(&scan)) {
			Hdr h = rd_next(&scan, "general name");
			if (h.cls != CLS_CONT) return 0;
			if (h.tag == 1 || h.tag == 2 || h.tag == 6) {
				if (h.cons) return 0;
			} else if (h.tag == 7) {
				if (h.cons || (h.len != 4 && h.len != 16)) return 0;
			} else {
				return 0;
			}
		}
		int printed = 0;
		while (rd_more(&i)) {
			Hdr h = rd_next(&i, "general name");
			const uint8_t *p = content(&h, b);
			if (printed) fputs(", ", stdout);
			printed = 1;
			switch (h.tag) {
			case 1: fputs("email:", stdout); fwrite(p, 1, h.len, stdout); break;
			case 2: fputs("DNS:", stdout);   fwrite(p, 1, h.len, stdout); break;
			case 6: fputs("URI:", stdout);   fwrite(p, 1, h.len, stdout); break;
			default:
				fputs("IP Address:", stdout);
				if (h.len == 4)
					printf("%u.%u.%u.%u", p[0], p[1], p[2], p[3]);
				else
					for (int g = 0; g < 8; g++)
						printf("%s%X", g ? ":" : "",
						       (p[2 * g] << 8) | p[2 * g + 1]);
			}
		}
		return 1;
	}
	return 0;
}

/* ------------------------------------------------------------- derx cert */

static void cmd_cert(const uint8_t *b, size_t n) {
	if (n == 0) die("empty input: no certificate");
	Rd file;
	file.b = b;
	file.i = 0;
	file.end = n;
	Hdr certh = rd_next(&file, "Certificate");
	expect(&certh, CLS_UNIV, 16, 1, "Certificate");
	rd_end(&file, "Certificate");
	Rd cert = rd_in(&file, &certh);

	Hdr tbsh = rd_next(&cert, "TBSCertificate");
	expect(&tbsh, CLS_UNIV, 16, 1, "TBSCertificate");
	Rd tbs = rd_in(&cert, &tbsh);

	/* version [0] EXPLICIT INTEGER DEFAULT v1. Absent means v1, which is
	 * the only field in the structure whose absence carries a value. */
	unsigned long version = 1;
	Hdr h = rd_peek(&tbs, "version");
	if (h.cls == CLS_CONT && h.tag == 0 && h.cons) {
		rd_next(&tbs, "version");
		Rd vr = rd_in(&tbs, &h);
		Hdr vi = rd_next(&vr, "version");
		rd_end(&vr, "version");
		version = small_int(&vi, b) + 1;
	}
	printf("version=%lu\n", version);

	Hdr serial = rd_next(&tbs, "serialNumber");
	expect(&serial, CLS_UNIV, 2, 0, "serialNumber");
	fputs("serial=", stdout);
	print_int(content(&serial, b), serial.len);
	putchar('\n');

	Hdr sigalg = rd_next(&tbs, "signature");
	expect(&sigalg, CLS_UNIV, 16, 1, "signature");
	{
		Rd ar = rd_in(&tbs, &sigalg);
		Hdr o = rd_next(&ar, "signature algorithm");
		char txt[OIDTEXTMAX];
		const char *d = oid_of(&o, b, txt);
		const char *ln = oid_ln(d);
		printf("sigalg=%s\n", ln ? ln : d);
	}

	Hdr issuer = rd_next(&tbs, "issuer");
	fputs("issuer=", stdout);
	print_name(&tbs, &issuer, "issuer");
	putchar('\n');

	Hdr val = rd_next(&tbs, "validity");
	expect(&val, CLS_UNIV, 16, 1, "validity");
	{
		Rd vr = rd_in(&tbs, &val);
		Hdr nb = rd_next(&vr, "notBefore");
		Hdr na = rd_next(&vr, "notAfter");
		rd_end(&vr, "validity");
		fputs("notBefore=", stdout);
		print_time(&nb, b, "notBefore");
		fputs("\nnotAfter=", stdout);
		print_time(&na, b, "notAfter");
		putchar('\n');
	}

	Hdr subject = rd_next(&tbs, "subject");
	fputs("subject=", stdout);
	print_name(&tbs, &subject, "subject");
	putchar('\n');

	Hdr spki = rd_next(&tbs, "subjectPublicKeyInfo");
	expect(&spki, CLS_UNIV, 16, 1, "subjectPublicKeyInfo");
	{
		Rd sr = rd_in(&tbs, &spki);
		Hdr algh = rd_next(&sr, "public key algorithm");
		expect(&algh, CLS_UNIV, 16, 1, "public key algorithm");
		Hdr keyh = rd_next(&sr, "subjectPublicKey");
		expect(&keyh, CLS_UNIV, 3, 0, "subjectPublicKey");
		rd_end(&sr, "subjectPublicKeyInfo");

		Rd ar = rd_in(&sr, &algh);
		Hdr o = rd_next(&ar, "public key algorithm");
		char txt[OIDTEXTMAX];
		const char *d = oid_of(&o, b, txt);
		const char *ln = oid_ln(d);
		printf("keyalg=%s\n", ln ? ln : d);

		/* A BIT STRING's first content octet counts the unused bits in
		 * its last. For a key it is always zero, and if it is not then
		 * the bytes below are not what they claim to be. */
		if (keyh.len == 0) die("subjectPublicKey: empty BIT STRING");
		if (content(&keyh, b)[0] != 0)
			die("subjectPublicKey: %u unused bits, expected 0",
			    content(&keyh, b)[0]);

		if (strcmp(d, "1.2.840.113549.1.1.1") == 0) {
			Rd kr;
			kr.b = b;
			kr.i = keyh.off + keyh.hl + 1;
			kr.end = keyh.off + keyh.hl + keyh.len;
			Hdr s = rd_next(&kr, "RSAPublicKey");
			expect(&s, CLS_UNIV, 16, 1, "RSAPublicKey");
			rd_end(&kr, "RSAPublicKey");
			Rd ir = rd_in(&kr, &s);
			Hdr mod = rd_next(&ir, "modulus");
			expect(&mod, CLS_UNIV, 2, 0, "modulus");
			printf("keybits=%lu\n", int_bits(&mod, b));
		} else if (strcmp(d, "1.2.840.10045.2.1") == 0) {
			Hdr par = rd_next(&ar, "EC parameters");
			char ct[OIDTEXTMAX];
			const char *cd = oid_of(&par, b, ct);
			unsigned bits = 0;
			for (size_t i = 0; i < sizeof curvebits / sizeof *curvebits; i++)
				if (strcmp(curvebits[i].oid, cd) == 0)
					bits = curvebits[i].bits;
			if (bits) printf("keybits=%u\n", bits);
			else fputs("keybits=-\n", stdout);
		} else {
			/* Ed25519 is the live example: openssl prints
			 * "ED25519 Public-Key:" with no bit count, so there is
			 * no number here for the oracle to agree with. */
			fputs("keybits=-\n", stdout);
		}
	}

	/* issuerUniqueID [1] and subjectUniqueID [2] are both IMPLICIT BIT
	 * STRINGs from X.509 v2 that RFC 5280 tells conforming CAs not to
	 * emit. Skipped rather than printed, and only after v2 or later. */
	while (rd_more(&tbs)) {
		Hdr t = rd_peek(&tbs, "TBSCertificate");
		if (t.cls == CLS_CONT && (t.tag == 1 || t.tag == 2) && !t.cons) {
			rd_next(&tbs, "uniqueID");
			continue;
		}
		break;
	}

	if (rd_more(&tbs)) {
		Hdr exts = rd_next(&tbs, "extensions");
		if (exts.cls != CLS_CONT || exts.tag != 3 || !exts.cons)
			die("extensions: expected [3] constructed at %zu", exts.off);
		Rd er = rd_in(&tbs, &exts);
		Hdr es = rd_next(&er, "extensions");
		expect(&es, CLS_UNIV, 16, 1, "extensions");
		rd_end(&er, "extensions");
		Rd lr = rd_in(&er, &es);
		while (rd_more(&lr)) {
			Hdr e = rd_next(&lr, "extension");
			expect(&e, CLS_UNIV, 16, 1, "extension");
			Rd ir = rd_in(&lr, &e);
			Hdr o = rd_next(&ir, "extnID");
			char txt[OIDTEXTMAX];
			const char *d = oid_of(&o, b, txt);
			int crit = 0;
			Hdr next = rd_next(&ir, "extension");
			if (next.cls == CLS_UNIV && next.tag == 1) {
				if (next.len != 1) die("critical flag is not one byte");
				crit = content(&next, b)[0] != 0;
				next = rd_next(&ir, "extnValue");
			}
			expect(&next, CLS_UNIV, 4, 0, "extnValue");
			rd_end(&ir, "extension");
			const char *ln = oid_ln(d);
			printf("ext=%s:%s:", ln ? ln : d, crit ? "critical" : "-");
			if (!print_ext_value(d, &ir, &next)) putchar('?');
			putchar('\n');
		}
	}
	rd_end(&tbs, "TBSCertificate");

	/* The outer signatureAlgorithm and signatureValue are read only far
	 * enough to confirm the structure; derx does no cryptography, so
	 * neither one has a meaning it could print. */
	Hdr outer = rd_next(&cert, "signatureAlgorithm");
	expect(&outer, CLS_UNIV, 16, 1, "signatureAlgorithm");
	Hdr sigval = rd_next(&cert, "signatureValue");
	expect(&sigval, CLS_UNIV, 3, 0, "signatureValue");
	rd_end(&cert, "Certificate");
}

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
	else if (strcmp(argv[1], "cert") == 0) cmd_cert(b, n);
	else usage();
	if (fflush(stdout) != 0) die("write error");
	free(b);
	return 0;
}
