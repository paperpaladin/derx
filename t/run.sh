#!/bin/sh
# The oracle. /usr/bin/openssl decides whether derx read the bytes correctly;
# there is no expected output anywhere in this file that was written by hand.
#
# Two kinds of assertion, and the difference matters:
#
#   agree NAME FILE     `derx parse FILE` is byte-identical to
#                       `openssl asn1parse -i -in FILE -inform DER`, and both
#                       accepted the input. This is the main oracle.
#   stricter NAME FILE  openssl accepts the input and derx rejects it. openssl
#                       reads BER; derx reads DER, which is a subset. Each of
#                       these is a deliberate divergence, and asserting
#                       openssl's acceptance is what keeps it a measured fact
#                       rather than a claim in the README.
#
# Plus `reject`, where both refuse, and two sweeps that assert only that derx
# never crashes -- which is the half of the contract openssl cannot help with.
set -u

# awk's printf "%c" is used to build the deep-nesting fixtures, and in a UTF-8
# locale gawk turns byte 255 into the two bytes of U+00FF. The fixtures are
# bytes, not text.
LC_ALL=C
export LC_ALL

ROOT=$(cd "$(dirname "$0")/.." && pwd)
D=${1:-$ROOT/derx}
T=$ROOT/t/tmp

pass=0; fail=0; skip=0; elements=0

ok()    { pass=$((pass + 1)); printf 'ok    %s\n' "$1"; }
bad()   { fail=$((fail + 1)); printf 'FAIL  %s\n' "$1"
          shift; [ $# -eq 0 ] || printf '%s\n' "$@" | sed 's/^/      | /'; }
skipt() { skip=$((skip + 1)); printf 'skip  %s  (%s)\n' "$1" "$2"; }

[ -x "$D" ] || { echo "run 'make' first" >&2; exit 2; }

# openssl is not a convenience here, it is the entire judge. Without it this
# file can only check derx against itself, which proves nothing, so a missing
# oracle is "cannot run" (exit 2) rather than a pass with everything skipped.
command -v openssl >/dev/null 2>&1 || {
	echo "openssl not found on PATH. It is the only oracle this suite has:" >&2
	echo "every expected value below comes from asn1parse or x509, so with" >&2
	echo "no openssl there is nothing to compare against and the suite" >&2
	echo "would be checking derx against derx. Refusing to report a pass." >&2
	exit 2
}
echo "oracle: $(openssl version)"
echo "under test: $D"
echo

rm -rf "$T"
mkdir -p "$T/corpus" || exit 2

# der FILE HEXBYTE...   write raw bytes. /bin/sh here is dash, whose printf
# has no \xNN, so the hex is converted to octal escapes first. Hand-built DER
# is spelled in hex because that is how the spec spells it.
der() {
	_f=$1; shift
	_o=''
	for _b in "$@"; do _o="$_o\\$(printf '%03o' "0x$_b")"; done
	printf '%b' "$_o" > "$_f"
}

# ---------------------------------------------------------------------------
# agree NAME FILE -- the main assertion: identical output, both accepting.
#
# The two status checks are not boilerplate. Without them a file that both
# programs reject would compare "no output" against "no output" and pass, so
# the vacuous case has to be an explicit failure.
# ---------------------------------------------------------------------------
agree() {
	_n=$1; _f=$2
	"$D" parse "$_f" > "$T/a.out" 2> "$T/a.err"; _ds=$?
	openssl asn1parse -i -in "$_f" -inform DER > "$T/b.out" 2>/dev/null; _os=$?
	if [ "$_ds" -ne 0 ]; then
		bad "$_n" "derx rejected it (exit $_ds)" "$(cat "$T/a.err")"; return
	fi
	if [ "$_os" -ne 0 ]; then
		bad "$_n" "openssl rejected it (exit $_os), so there is nothing to agree with"
		return
	fi
	_lines=$(wc -l < "$T/b.out")
	if [ "$_lines" -lt 1 ]; then
		bad "$_n" "oracle printed nothing: this comparison would be vacuous"
		return
	fi
	elements=$((elements + _lines))
	if cmp -s "$T/a.out" "$T/b.out"; then ok "$_n"
	else bad "$_n" "$(diff "$T/b.out" "$T/a.out" | head -14)"; fi
}

# reject NAME FILE [openssl_status] -- derx must exit 1 and say why. The third
# argument is what openssl does with the same bytes, asserted so the suite
# records whether this is a shared judgement or ours alone.
reject() {
	_n=$1; _f=$2; _want=${3:-1}
	"$D" parse "$_f" > "$T/a.out" 2> "$T/a.err"; _ds=$?
	openssl asn1parse -i -in "$_f" -inform DER >/dev/null 2>&1; _os=$?
	if [ "$_ds" -ne 1 ]; then
		bad "$_n" "want derx exit 1, got $_ds" "$(cat "$T/a.err")"; return
	fi
	if ! grep -q '^derx: ' "$T/a.err"; then
		bad "$_n" "exit 1 but no 'derx: ' diagnostic on stderr"; return
	fi
	if [ "$_os" -ne "$_want" ]; then
		bad "$_n" "openssl exit $_os, expected $_want: the oracle changed its mind"
		return
	fi
	ok "$_n"
}

# stricter NAME FILE -- openssl accepts (exit 0), derx refuses. DER is a
# subset of BER and these are the places it is a strict subset.
stricter() { reject "$1" "$2" 0; }

# ===========================================================================
# 1. the universal tag names, 0 through 30, against ASN1_tag2str
# ===========================================================================
# openssl's spelling is not the standard's: tag 20 is TeletexString in X.680
# and "T61STRING" here, tag 26 is VisibleString and "VISIBLESTRING" here, and
# tags 11, 13, 14, 15 and 29 have no name at all and print as "<ASN1 n>".
# There is no way to derive that list; it has to be compared entry by entry.
i=0
while [ "$i" -le 30 ]; do
	case $i in
	# A BOOLEAN of three bytes is not DER, so this one tag needs content
	# that is; the content is irrelevant to what is being asserted.
	1)       der "$T/tag.der" 01 01 ff ;;
	# EXTERNAL, SEQUENCE and SET are SEQUENCE types and may only be
	# constructed, so the identifier octet gets 0x20 and the content is
	# empty rather than the letters "abc".
	8|16|17) der "$T/tag.der" "$(printf '%02x' $((i + 32)))" 00 ;;
	*)       der "$T/tag.der" "$(printf '%02x' "$i")" 03 61 62 63 ;;
	esac
	agree "tag $i: the name openssl prints" "$T/tag.der"
	i=$((i + 1))
done

# ===========================================================================
# 2. the other three tag classes, and the high-tag-number form
# ===========================================================================
der "$T/x.der" 40 01 41;             agree 'application class, primitive'   "$T/x.der"
der "$T/x.der" 60 02 05 00;          agree 'application class, constructed' "$T/x.der"
der "$T/x.der" 82 03 61 62 63;       agree 'context class, primitive'       "$T/x.der"
der "$T/x.der" a2 05 04 03 61 62 63; agree 'context class, constructed'     "$T/x.der"
der "$T/x.der" e0 02 05 00;          agree 'private class, constructed'     "$T/x.der"
# Tag numbers above 30 travel as base-128 continuation bytes. 0x1f 0x81 0x01
# is universal tag 129; 0x9f 0x24 is context tag 36.
der "$T/x.der" 1f 81 01 00;          agree 'high tag number, universal 129' "$T/x.der"
der "$T/x.der" 9f 24 01 41;          agree 'high tag number, context 36'    "$T/x.der"
der "$T/x.der" 30 06 9f 24 01 41 05 00
                                     agree 'high tag number nested'         "$T/x.der"

# ===========================================================================
# 3. values, at the boundaries that are easy to get wrong
# ===========================================================================
der "$T/x.der" 02 01 00;             agree 'INTEGER 0'                 "$T/x.der"
der "$T/x.der" 02 01 7f;             agree 'INTEGER 127'               "$T/x.der"
der "$T/x.der" 02 02 00 80;          agree 'INTEGER 128, sign padded'  "$T/x.der"
der "$T/x.der" 02 01 ff;             agree 'INTEGER -1'                "$T/x.der"
der "$T/x.der" 02 01 80;             agree 'INTEGER -128'              "$T/x.der"
der "$T/x.der" 02 02 80 00;          agree 'INTEGER -32768'            "$T/x.der"
# -512 is FE 00: openssl keeps the low zero byte of the magnitude and prints
# -0200, where FF 00 01 negates to 00 FF FF and it drops the high one.
der "$T/x.der" 02 02 fe 00;          agree 'INTEGER -512, kept zero byte' "$T/x.der"
der "$T/x.der" 02 03 ff 00 01;       agree 'INTEGER -65535, dropped zero byte' "$T/x.der"
der "$T/x.der" 02 09 00 ff ff ff ff ff ff ff ff
                                     agree 'INTEGER 2^64-1'            "$T/x.der"
der "$T/x.der" 0a 01 ff;             agree 'ENUMERATED -1'             "$T/x.der"
der "$T/x.der" 01 01 ff;             agree 'BOOLEAN true prints 255'   "$T/x.der"
der "$T/x.der" 01 01 00;             agree 'BOOLEAN false'             "$T/x.der"
der "$T/x.der" 04 00;                agree 'OCTET STRING empty, no colon' "$T/x.der"
der "$T/x.der" 04 05 68 65 6c 6c 6f; agree 'OCTET STRING printable as text' "$T/x.der"
der "$T/x.der" 04 02 61 7f;          agree 'OCTET STRING 0x7f is not printable' "$T/x.der"
der "$T/x.der" 04 03 61 09 62;       agree 'OCTET STRING tab is printable' "$T/x.der"
der "$T/x.der" 04 03 61 01 62;       agree 'OCTET STRING 0x01 forces hex dump' "$T/x.der"
der "$T/x.der" 13 00;                agree 'PRINTABLESTRING empty prints colon' "$T/x.der"
der "$T/x.der" 03 04 00 de ad be;    agree 'BIT STRING prints no value'  "$T/x.der"
der "$T/x.der" 1e 04 00 61 00 62;    agree 'BMPSTRING prints no value'   "$T/x.der"
der "$T/x.der" 05 00;               agree 'NULL'                       "$T/x.der"

# OIDs. The 40*X+Y unpacking caps X at 2, so every first-arc value from 80 up
# belongs to X=2 and Y runs past 39 -- 2.999 encodes as the single arc 1079.
der "$T/x.der" 06 01 00;             agree 'OID 0.0'                   "$T/x.der"
der "$T/x.der" 06 01 27;             agree 'OID 0.39'                  "$T/x.der"
der "$T/x.der" 06 01 28;             agree 'OID 1.0'                   "$T/x.der"
der "$T/x.der" 06 01 50;             agree 'OID 2.0'                   "$T/x.der"
der "$T/x.der" 06 02 88 37;          agree 'OID 2.999, not 26.39'      "$T/x.der"
der "$T/x.der" 06 03 55 04 03;       agree 'OID named: commonName'     "$T/x.der"
der "$T/x.der" 06 09 2a 86 48 86 f7 0d 01 01 0b
                                     agree 'OID named: sha256WithRSAEncryption' "$T/x.der"
der "$T/x.der" 06 0b 2b 06 01 04 01 82 37 15 01 00 01
                                     agree 'OID unnamed prints dotted' "$T/x.der"
der "$T/x.der" 06 0a 2a 90 80 80 80 80 80 80 80 00
                                     agree 'OID arc 2^60'              "$T/x.der"
# The one that a uint64 accumulator gets wrong rather than refusing: openssl
# uses a BIGNUM here, and this arc is 2^71.
der "$T/x.der" 06 0c 2a 82 80 80 80 80 80 80 80 80 80 00
                                     agree 'OID arc wider than 64 bits' "$T/x.der"

# ===========================================================================
# 4. generated certificates and keys: real DER from the oracle's own encoder
# ===========================================================================
gen() { # gen NAME ARGS...  produce $T/NAME.der from openssl req -x509
	_name=$1; shift
	if openssl req -x509 -nodes -keyout "$T/$_name.key" \
	     -outform DER -out "$T/$_name.der" "$@" >/dev/null 2>&1; then
		agree "cert: $_name" "$T/$_name.der"
	else
		skipt "cert: $_name" "openssl req refused these arguments"
	fi
}

gen rsa2048-sha256 -newkey rsa:2048 -sha256 -days 365 -subj '/CN=derx test/O=Example Org/C=US'
gen rsa1024-sha1   -newkey rsa:1024 -sha1   -days 30  -subj '/CN=old'
gen rsa3072-sha512 -newkey rsa:3072 -sha512 -days 365 -subj '/CN=big'
gen ec256-sha256   -newkey ec -pkeyopt ec_paramgen_curve:P-256 -sha256 -days 365 -subj '/CN=p256'
gen ec384-sha384   -newkey ec -pkeyopt ec_paramgen_curve:P-384 -sha384 -days 365 -subj '/CN=p384'
gen ec521-sha512   -newkey ec -pkeyopt ec_paramgen_curve:P-521 -sha512 -days 365 -subj '/CN=p521'
gen ed25519        -newkey ed25519 -days 365 -subj '/CN=ed25519'
# notAfter past 2049 forces GeneralizedTime instead of UTCTime (RFC 5280
# 4.1.2.5): two different time encodings in one certificate is a case no
# hand-written fixture would think to build.
gen longvalidity   -newkey rsa:2048 -sha256 -days 20000 -subj '/CN=year 2081'
gen manyattrs      -newkey rsa:2048 -sha256 -days 365 \
	-subj '/CN=a/O=b/OU=c/C=US/L=d/ST=e/street=f/postalCode=g/title=h/SN=i/GN=j/initials=k/businessCategory=l/serialNumber=m/emailAddress=n@o/DC=p/UID=q/dnQualifier=r/pseudonym=s/organizationIdentifier=t/description=u/name=v/generationQualifier=w/x500UniqueIdentifier=y'
gen dn-comma       -newkey rsa:2048 -sha256 -days 365 -subj '/CN=a,b/O=Example, Inc./C=US'
gen dn-spaces      -newkey rsa:2048 -sha256 -days 365 -subj '/CN=  padded  /O=x'
gen dn-utf8        -newkey rsa:2048 -sha256 -days 365 -subj '/CN=hello/O=non ascii'
gen dn-multivalue  -newkey rsa:2048 -sha256 -days 365 -multivalue-rdn -subj '/CN=a+O=b'
gen ext-san        -newkey rsa:2048 -sha256 -days 365 -subj '/CN=san' \
	-addext 'subjectAltName=DNS:a.example,DNS:b.example,IP:10.0.0.1,email:x@y.z,URI:https://q.example/p'
gen ext-ku         -newkey rsa:2048 -sha256 -days 365 -subj '/CN=ku' \
	-addext 'keyUsage=critical,digitalSignature,keyEncipherment,keyAgreement' \
	-addext 'extendedKeyUsage=serverAuth,clientAuth,codeSigning' \
	-addext 'basicConstraints=critical,CA:TRUE,pathlen:3'
gen ext-leaf       -newkey rsa:2048 -sha256 -days 365 -subj '/CN=leaf' \
	-addext 'basicConstraints=CA:FALSE' -addext 'keyUsage=digitalSignature'

# Other DER the oracle can emit, to get shapes a certificate never contains.
if openssl req -new -nodes -newkey rsa:2048 -keyout "$T/csr.key" -sha256 \
     -subj '/CN=csr' -outform DER -out "$T/csr.der" >/dev/null 2>&1; then
	agree 'certificate request (PKCS#10)' "$T/csr.der"
else
	skipt 'certificate request (PKCS#10)' 'openssl req -new failed'
fi
if openssl rsa -in "$T/rsa2048-sha256.key" -traditional -outform DER \
     -out "$T/rsakey.der" >/dev/null 2>&1; then
	# Nine INTEGERs, each 128 or 256 bytes: the widest integers in the suite.
	agree 'RSA private key (PKCS#1)' "$T/rsakey.der"
else
	skipt 'RSA private key (PKCS#1)' 'openssl rsa failed'
fi
if openssl pkcs8 -topk8 -nocrypt -in "$T/rsa2048-sha256.key" -outform DER \
     -out "$T/pkcs8.der" >/dev/null 2>&1; then
	# PrivateKeyInfo buries the key in an OCTET STRING, which openssl shows
	# as a hex dump rather than descending into: the long [HEX DUMP] path.
	agree 'PKCS#8 PrivateKeyInfo' "$T/pkcs8.der"
else
	skipt 'PKCS#8 PrivateKeyInfo' 'openssl pkcs8 failed'
fi
if openssl ec -in "$T/ec384-sha384.key" -outform DER -out "$T/eckey.der" \
     >/dev/null 2>&1; then
	agree 'EC private key' "$T/eckey.der"
else
	skipt 'EC private key' 'openssl ec failed'
fi
if openssl ecparam -name secp384r1 -outform DER -out "$T/ecparam.der" \
     >/dev/null 2>&1; then
	agree 'EC parameters (a bare OID)' "$T/ecparam.der"
else
	skipt 'EC parameters (a bare OID)' 'openssl ecparam failed'
fi

# ===========================================================================
# 5. the certificates already on this machine
# ===========================================================================
# Real-world DER, issued by real CAs over twenty-five years, carrying encoders'
# habits that nothing generated locally reproduces -- T61Strings,
# GeneralizedTime in a root from 2011, OIDs openssl itself cannot name. This
# is the group that finds what the fixtures cannot. Read-only.
CERTDIR=/etc/ssl/certs
ncert=0
if [ -d "$CERTDIR" ]; then
	for f in "$CERTDIR"/*.pem; do
		[ -f "$f" ] || continue
		b=$(basename "$f" .pem)
		openssl x509 -in "$f" -inform PEM -outform DER \
			-out "$T/corpus/$b.der" 2>/dev/null || continue
		ncert=$((ncert + 1))
	done
fi
# A loop over an empty glob is the classic silent pass, so the count is an
# assertion and not a note. 100 is well under the 150 present, so a thinned
# trust store still runs; an absent one fails loudly.
if [ "$ncert" -lt 100 ]; then
	bad "system trust store has at least 100 certificates" \
	    "found $ncert under $CERTDIR -- the corpus comparison below would be vacuous"
else
	ok "system trust store: $ncert certificates converted to DER"
	cbad=0; cfirst=''
	celem=0
	for f in "$T"/corpus/*.der; do
		"$D" parse "$f" > "$T/a.out" 2>"$T/a.err"
		openssl asn1parse -i -in "$f" -inform DER > "$T/b.out" 2>/dev/null
		if cmp -s "$T/a.out" "$T/b.out"; then
			celem=$((celem + $(wc -l < "$T/b.out")))
		else
			cbad=$((cbad + 1))
			if [ -z "$cfirst" ]; then
				cfirst=$f
				cp "$T/a.out" "$T/c-derx.out"
				cp "$T/b.out" "$T/c-ssl.out"
			fi
		fi
	done
	elements=$((elements + celem))
	# Both halves are assertions. Zero differing certificates is the claim;
	# thousands of elements compared is the guard that the claim was
	# actually tested, because a loop that parses nothing differs from
	# nothing either.
	if [ "$celem" -le 5000 ]; then
		bad "$CERTDIR: elements byte-identical to asn1parse" \
		    "only $celem elements compared across $ncert certificates:" \
		    "expected thousands, so the comparison is not running"
	elif [ "$cbad" -ne 0 ]; then
		bad "$CERTDIR: $cbad of $ncert certificates differ" \
		    "first mismatch: $cfirst" \
		    "$(diff "$T/c-ssl.out" "$T/c-derx.out" 2>/dev/null | head -10)"
	else
		ok "$CERTDIR: $celem elements byte-identical to asn1parse"
	fi
fi

# ===========================================================================
# 6. malformed input: both programs refuse
# ===========================================================================
der "$T/m.der" 30
reject 'truncated: identifier with no length' "$T/m.der"
der "$T/m.der" 30 05 05 00
reject 'truncated: content shorter than length' "$T/m.der"
# Short by exactly one byte. Three bytes missing is caught by a bounds check
# that is off by one; one byte missing is not, and it is the overread that
# actually happens -- a length field describing one more byte than arrived.
der "$T/m.der" 04 03 61 62
reject 'truncated: content short by exactly one byte' "$T/m.der"
# Same, but one level down, so the byte past the end is a sibling's tag rather
# than a byte past the allocation. ASan cannot see this one; the oracle can.
der "$T/m.der" 30 04 04 03 61 62 05 00
reject 'child short by one byte reads into its sibling' "$T/m.der"
der "$T/m.der" 04 82 01
reject 'truncated: long-form length cut short' "$T/m.der"
der "$T/m.der" 04 84 7f ff ff ff 41
reject 'length declares 2GB in a 7 byte file' "$T/m.der"
# The SEQUENCE declares two content bytes and the OCTET STRING inside it
# declares five. Caught because hdr() is given the parent's end rather than
# the file's: with the file's end this would read into whatever follows.
der "$T/m.der" 30 02 04 05
reject 'child runs past its parent' "$T/m.der"
der "$T/m.der" 05 00 ff
reject 'trailing garbage after a complete element' "$T/m.der"
der "$T/m.der" 04 ff 41
reject 'length octet 0xff is reserved' "$T/m.der"
: > "$T/m.der"
reject 'empty input' "$T/m.der"
der "$T/m.der" 1f ff ff ff ff ff ff ff ff ff 7f 00
reject 'tag number too wide to represent' "$T/m.der"

# A chain of nested SEQUENCEs, each a valid wrapper for the next, is the
# shape that turns recursion into a stack overflow. openssl stops at a
# printed depth of 128 (ASN1_PARSE_MAXDEPTH) and so does derx, so both the
# accepted and the refused side of that boundary are the oracle's call.
# Built by awk rather than by der(), which spends a subprocess per byte: at
# 4000 levels that is 16000 of them. awk emits the headers outermost-first
# after computing the lengths innermost-first.
nest() { # nest FILE DEPTH -- DEPTH SEQUENCEs wrapping a NULL
	awk -v d="$2" 'function emit(c) { printf "%c", c }
	BEGIN {
		n = 2; k = 0
		for (i = 0; i < d; i++) {
			if (n < 128)      { hdr[k++] = sprintf("48 %d", n); n += 2 }
			else if (n < 256) { hdr[k++] = sprintf("48 129 %d", n); n += 3 }
			else              { hdr[k++] = sprintf("48 130 %d %d", \
						int(n / 256), n % 256); n += 4 }
		}
		for (i = k - 1; i >= 0; i--) {
			split(hdr[i], f, " ")
			for (j = 1; j in f; j++) emit(f[j] + 0)
		}
		emit(5); emit(0)
	}' > "$1"
}
nest "$T/n128.der" 128
agree 'nesting 128 deep, accepted by both' "$T/n128.der"
nest "$T/n129.der" 129
reject 'nesting 129 deep, refused by both' "$T/n129.der"
nest "$T/n4000.der" 4000
reject 'nesting 4000 deep is a diagnostic, not a stack overflow' "$T/n4000.der"

# ===========================================================================
# 7. valid BER that is not valid DER: openssl accepts, derx refuses
# ===========================================================================
# Every one of these is a second encoding of a value that DER already has one
# encoding for. The assertion includes openssl's exit 0, so "openssl is more
# permissive here" stays a measured fact.
der "$T/s.der" 30 80 05 00 00 00
stricter 'indefinite length (BER only)'              "$T/s.der"
der "$T/s.der" 04 81 05 68 65 6c 6c 6f
stricter 'long-form length for a length under 128'   "$T/s.der"
der "$T/s.der" 04 89 00 00 00 00 00 00 00 00 01 41
stricter 'long-form length with leading zero octets' "$T/s.der"
der "$T/s.der" 02 02 00 7f
stricter 'INTEGER with a redundant leading 00'       "$T/s.der"
der "$T/s.der" 02 02 ff ff
stricter 'INTEGER with a redundant leading FF'       "$T/s.der"
der "$T/s.der" 02 00
stricter 'INTEGER of zero length'                    "$T/s.der"
der "$T/s.der" 01 01 01
stricter 'BOOLEAN true encoded as 01, not FF'        "$T/s.der"
der "$T/s.der" 01 02 ff ff
stricter 'BOOLEAN of two bytes'                      "$T/s.der"
der "$T/s.der" 06 00
stricter 'OID of zero length'                        "$T/s.der"
der "$T/s.der" 06 03 2a 80 01
stricter 'OID arc padded with a zero septet'         "$T/s.der"
der "$T/s.der" 06 04 2a 86 48 87
stricter 'OID content ending mid-arc'                "$T/s.der"
der "$T/s.der" 24 06 04 01 61 04 01 62
stricter 'constructed OCTET STRING (BER segmenting)' "$T/s.der"
der "$T/s.der" 9f 80 01 00
stricter 'high tag number padded with a zero septet' "$T/s.der"
der "$T/s.der" 5f 01 00
stricter 'high tag number form used for tag 1'       "$T/s.der"

# ===========================================================================
# 8. the half openssl cannot judge: derx never crashes
# ===========================================================================
# Exit status 0 means parsed, 1 means refused, 2 means a usage error. Anything
# else is a defect: 86 is the sanitizers (see the Makefile -- that number
# exists because a sanitizer abort otherwise exits 1 and is indistinguishable
# from a clean refusal), and anything above 128 is death by signal.
sweep() { # sweep NAME DIR -- run derx over every file, assert status <= 2
	_n=$1; _dir=$2; _bad=0; _cnt=0; _worst=''
	for _f in "$_dir"/*; do
		[ -f "$_f" ] || continue
		_cnt=$((_cnt + 1))
		"$D" parse "$_f" >/dev/null 2>&1; _s=$?
		if [ "$_s" -gt 2 ]; then
			_bad=$((_bad + 1)); _worst="$_f exited $_s"
		fi
	done
	if [ "$_cnt" -lt 2 ]; then
		bad "$_n" "only $_cnt inputs swept: this assertion is vacuous"
	elif [ "$_bad" -eq 0 ]; then
		ok "$_n ($_cnt inputs)"
	else
		bad "$_n" "$_bad of $_cnt inputs exited above 2" "$_worst"
	fi
}

# Every prefix of a real certificate. A length field read before the bytes it
# describes have arrived is the classic overread, and this walks every single
# place that can happen in one file.
mkdir -p "$T/trunc"
full="$T/rsa1024-sha1.der"
if [ -f "$full" ]; then
	size=$(wc -c < "$full")
	k=0
	while [ "$k" -lt "$size" ]; do
		head -c "$k" "$full" > "$T/trunc/$k"
		k=$((k + 1))
	done
	sweep "truncation sweep: every prefix of a certificate" "$T/trunc"
else
	skipt 'truncation sweep' 'no generated certificate to truncate'
fi

# One byte of a real certificate replaced by 00 and by FF, at every offset.
# Corrupting a length or a tag in place is how you reach a code path that the
# structurally-valid corpus never touches.
mkdir -p "$T/mut"
if [ -f "$full" ]; then
	k=0
	while [ "$k" -lt "$size" ]; do
		for v in 00 ff; do
			cp "$full" "$T/mut/$k-$v"
			der "$T/byte" "$v"
			dd if="$T/byte" of="$T/mut/$k-$v" bs=1 seek="$k" \
				count=1 conv=notrunc status=none
		done
		k=$((k + 1))
	done
	sweep "single-byte corruption sweep: 00 and FF at every offset" "$T/mut"
else
	skipt 'single-byte corruption sweep' 'no generated certificate to corrupt'
fi

printf '\n%d passed, %d failed, %d skipped\n' "$pass" "$fail" "$skip"
printf '%d DER elements compared against openssl asn1parse\n' "$elements"
[ "$fail" -eq 0 ]
