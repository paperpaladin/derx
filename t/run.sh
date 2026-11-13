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
# The trust store's share of $elements, kept apart so the fixtures' share can
# be asserted on its own: 9,627 of the 10,891 come from /etc/ssl/certs and
# move with whatever is installed there, where the rest are built here.
celem=0

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
# 1b. the primitive-only and constructed-only rules, one assertion per tag
# ===========================================================================
# derx.c classifies 25 of the 31 universal tags: 22 may only be primitive,
# since BER's constructed string form is a second encoding of one value, and
# 3 are SEQUENCE types that may only be constructed. The suite drove exactly
# one of those 25 bits before this block, the constructed OCTET STRING in
# section 8, so 24 of them were a mask in the source that nothing read: a
# table enumerated rather than exercised, which is the shape `vtparse` found
# in its own published state table.
#
# Measured per bit, by compiling 25 copies of derx with one term removed from
# the mask: dropping bit N makes derx accept the wrong form of tag N and
# nothing else, so each of the 25 assertions below kills exactly one of them.
#
# openssl read every wrong-form element it was shown, all 31 tags in both
# forms, exit 0 every time, so all 25 are places derx is stricter, and
# `stricter` asserts openssl's acceptance beside derx's refusal. The six tags
# openssl has no name for are classified neither way on purpose: both forms
# of those agree instead, which turns "the oracle has no opinion" into
# something the suite would notice losing.
for t in 1 2 3 4 5 6 7 9 10 12 18 19 20 21 22 23 24 25 26 27 28 30; do
	der "$T/f.der" "$(printf '%02x' $((t + 32)))" 02 05 00
	stricter "universal tag $t may not be constructed" "$T/f.der"
done
for t in 8 16 17; do
	der "$T/f.der" "$(printf '%02x' "$t")" 03 61 62 63
	stricter "universal tag $t may not be primitive" "$T/f.der"
done
for t in 0 11 13 14 15 29; do
	der "$T/f.der" "$(printf '%02x' $((t + 32)))" 02 05 00
	agree "universal tag $t is classified neither way" "$T/f.der"
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
# 3b. every row of the OID name table
# ===========================================================================
# The comment above oidtab[] in derx.c said every row of it was verified by
# diff. That was true of 55 rows. A row is checked only when some input
# carries the OID, and 14 of the 69 are carried by nothing in /etc/ssl/certs,
# nothing openssl's generator emits and no hand-built fixture: rsassaPss,
# ecdsa-with-SHA1, ED448, seven extension names from Subject Directory
# Attributes to Inhibit Any Policy, and four of the seven extended key usage
# purposes. Those were typed and never read back, which is the shape a table
# in a repository has when it is enumerated rather than exercised.
#
# So each row supplies its own input. openssl encodes the dotted form with
# `asn1parse -genstr`, openssl names it back, and derx has to print the same
# line. A misspelled name fails; so does a wrong dotted value, because the
# name comes from the OID that was actually encoded, not from the one that
# was meant.
#
# The rows are read out of derx.c rather than copied here, because the table
# is the thing being exercised and a copy would be a second table to keep in
# step. Two counts guard the reading, deliberately by different patterns: the
# rows the sed understood must equal the lines in the block that hold a
# quoted string, so a row written in another shape cannot be skipped in
# silence, and 69 is a floor, so an extraction that matched nothing cannot
# report a pass.
oidrows=$(awk '/^static const struct .* oidtab\[\] = \{/,/^\};/' "$ROOT/derx.c" |
          sed -n 's/^	{ *"\([^"]*\)".*/\1/p')
oidn=$(printf '%s\n' "$oidrows" | sed '/^$/d' | wc -l)
oidq=$(awk '/^static const struct .* oidtab\[\] = \{/,/^\};/' "$ROOT/derx.c" |
       grep -c '"')
if [ "$oidn" -ne "$oidq" ] || [ "$oidn" -lt 69 ]; then
	bad 'OID table rows read out of derx.c' \
	    "$oidn dotted values parsed out of $oidq rows in the block, floor 69" \
	    'a row the sed cannot read is a row this group does not exercise'
else
	ok "OID table: $oidn rows read out of derx.c"
	for dot in $oidrows; do
		if openssl asn1parse -genstr "OID:$dot" -out "$T/oid.der" \
		     -noout 2>/dev/null; then
			agree "OID table row $dot" "$T/oid.der"
		else
			# Not a skip: a dotted value openssl will not encode
			# is not an OID, whatever the table says.
			bad "OID table row $dot" \
			    'openssl asn1parse -genstr refused to encode it'
		fi
	done
fi

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
# 6. derx cert, against three different openssl subcommands
# ===========================================================================
# The nine non-extension fields are compared as nine whole lines. Five of
# them are free: `openssl x509 -serial -issuer -subject -startdate -enddate`
# prints exactly "serial=", "issuer=", "subject=", "notBefore=" and
# "notAfter=", so derx uses those spellings and the comparison is a diff with
# no normalisation on either side. The other four -- version, sigalg, keyalg,
# keybits -- have no one-line flag and are extracted from -text.
#
# -nameopt RFC2253 rather than openssl's default, for one reason: RFC 2253 is
# a published specification with escaping rules that can be implemented from
# the document, where the default output is openssl's own habits and matching
# those would be imitation rather than agreement.
oracle_fields() { # oracle_fields FILE -> the nine lines, in derx's order
	openssl x509 -in "$1" -inform DER -noout -text > "$T/txt" 2>/dev/null
	sed -n 's/^ *Version: \([0-9]*\).*/version=\1/p' "$T/txt" | head -1
	openssl x509 -in "$1" -inform DER -noout -serial
	sed -n 's/^ *Signature Algorithm: /sigalg=/p' "$T/txt" | head -1
	openssl x509 -in "$1" -inform DER -noout -nameopt RFC2253 -issuer
	openssl x509 -in "$1" -inform DER -noout -startdate -enddate
	openssl x509 -in "$1" -inform DER -noout -nameopt RFC2253 -subject
	sed -n 's/^ *Public Key Algorithm: /keyalg=/p' "$T/txt" | head -1
	# Ed25519 is the live case where openssl states no key size at all, so
	# "-" is the only honest value and the absence is itself asserted.
	_kb=$(sed -n 's/^ *Public-Key: (\([0-9]*\) bit)/keybits=\1/p' "$T/txt" | head -1)
	if [ -n "$_kb" ]; then echo "$_kb"; else echo 'keybits=-'; fi
}

# The extension names and critical flags, in encoding order, out of -text.
oracle_extnames() {
	awk '/^ {8}X509v3 extensions:/ { e = 1; next }
	     e && /^ {4}[A-Za-z]/      { e = 0 }
	     e && /^ {12}[^ ]/ {
		s = $0; sub(/^ {12}/, "", s); c = "-"
		if (sub(/: critical$/, "", s)) c = "critical"
		else sub(/: *$/, "", s)
		printf "ext=%s:%s\n", s, c
	     }' "$1"
}

certfields() { # certfields NAME FILE
	_n=$1; _f=$2
	if ! "$D" cert "$_f" > "$T/d.all" 2> "$T/d.err"; then
		bad "$_n" "derx cert exited $?" "$(cat "$T/d.err")"; return
	fi
	grep -v '^ext=' "$T/d.all" > "$T/d.out"
	oracle_fields "$_f" > "$T/o.out"
	# Nine, every time. Fewer means a sed above stopped matching and the
	# comparison silently shrank to the fields that still worked.
	if [ "$(wc -l < "$T/o.out")" -ne 9 ]; then
		bad "$_n" "the oracle produced $(wc -l < "$T/o.out") field lines, not 9" \
		    "$(cat "$T/o.out")"
		return
	fi
	if ! cmp -s "$T/d.out" "$T/o.out"; then
		bad "$_n" "$(diff "$T/o.out" "$T/d.out")"; return
	fi
	# And the extension names and critical flags in order.
	sed -E -n 's/^ext=([^:]*:(critical|-)):.*/ext=\1/p' "$T/d.all" > "$T/d.ext"
	oracle_extnames "$T/txt" > "$T/o.ext"
	if ! cmp -s "$T/d.ext" "$T/o.ext"; then
		bad "$_n" "extension names differ" "$(diff "$T/o.ext" "$T/d.ext")"; return
	fi
	ok "$_n"
}

# One extension's value, as openssl renders it on its own, normalised into
# derx's one-line form. Status 1 means the certificate does not carry it, 2
# means openssl needed more than one line for the value and this format
# cannot represent it.
oracle_ext() { # oracle_ext FILE SHORTNAME
	openssl x509 -in "$1" -inform DER -noout -ext "$2" 2>/dev/null > "$T/e.txt"
	[ -s "$T/e.txt" ] || return 1
	[ "$(wc -l < "$T/e.txt")" -eq 2 ] || return 2
	awk 'NR == 1 { c = "-"; s = $0
		       if (sub(/: critical$/, "", s)) c = "critical"
		       else sub(/: *$/, "", s)
		       n = s }
	     NR == 2 { v = $0; sub(/^ */, "", v); printf "%s:%s:%s\n", n, c, v }' \
		"$T/e.txt"
	return 0
}

EXTSN='basicConstraints keyUsage extendedKeyUsage subjectKeyIdentifier
       authorityKeyIdentifier subjectAltName'

# Counted per extension, because one total over six of them cannot tell an
# extension carried by every certificate from one carried by none. It was
# hiding exactly that: extendedKeyUsage appears in 0 of the 150 certificates
# in the trust store, contributes 0 of the 477 agreements, and nothing in this
# file said so. Three extensions supply 446 of the 477 between them, so the
# total tracks those three and absorbs the rest.
#
# Two groups, kept apart because their floors are of different kinds. The
# generated and hand-built fixtures are inputs this file builds, so their
# counts are fixed and asserted as equalities. The trust store is not ours,
# so each extension gets a floor that scales with $ncert.
for _sn in $EXTSN; do eval "fx_$_sn=0 ag_$_sn=0 dc_$_sn=0"; done

# certexts NAME FILE -- every supported extension the file carries must match
# openssl exactly. Used on the generated fixtures, where declining to decode
# is not an acceptable answer, so a derx that answered "?" to everything would
# fail here.
certexts() {
	_n=$1; _f=$2; _cmp=0
	"$D" cert "$_f" > "$T/d.all" 2>/dev/null
	for _sn in $EXTSN; do
		_o=$(oracle_ext "$_f" "$_sn") || continue
		_name=${_o%%:*}
		_d=$(grep "^ext=$_name:" "$T/d.all")
		if [ "ext=$_o" != "$_d" ]; then
			bad "$_n" "$_sn:" "  oracle: ext=$_o" "  derx:   $_d"
			return
		fi
		eval "fx_$_sn=\$((fx_$_sn + 1))"
		_cmp=$((_cmp + 1))
	done
	if [ "$_cmp" -lt 1 ]; then
		bad "$_n" "no extension was compared: this assertion is vacuous"
	else
		ok "$_n ($_cmp extensions)"
	fi
}

for c in rsa2048-sha256 rsa1024-sha1 rsa3072-sha512 ec256-sha256 ec384-sha384 \
         ec521-sha512 ed25519 longvalidity manyattrs dn-comma dn-spaces \
         dn-utf8 dn-multivalue ext-san ext-ku ext-leaf; do
	# A fixture openssl's generator refused is two assertions that never
	# run, and `continue` left nothing behind to say so: the suite simply
	# reported a smaller number. Counted as skips, so the assertion total
	# at the bottom of this file holds on a machine whose openssl refuses
	# an argument -- a 1024-bit key and SHA-1 are both candidates.
	if [ -f "$T/$c.der" ]; then
		certfields "cert fields: $c" "$T/$c.der"
		certexts   "cert extensions: $c" "$T/$c.der"
	else
		skipt "cert fields: $c"     'the fixture was not generated'
		skipt "cert extensions: $c" 'the fixture was not generated'
	fi
done

# ---------------------------------------------------------------------------
# A certificate assembled by hand, byte by byte, because openssl's own
# generator will not produce any of these and they are all real code paths:
#
#   - no version field at all, which is how a v1 certificate is encoded. The
#     absence carries the value, and nothing in /etc/ssl/certs is v1.
#   - an attribute type openssl has no name for (1.2.3.4), which it prints as
#     the dotted OID with the value dumped as "#" plus the hex of the whole
#     DER element, header included.
#   - a 16-bit RSA modulus, so the bit-length calculation is checked somewhere
#     other than a round 2048.
#
# openssl verifies no signature to print these fields, so the signature here
# is the four bytes DE AD BE EF and that is fine.
# ---------------------------------------------------------------------------
der "$T/hand.der" \
 30 81 a7 30 81 8e 02 01 01 30 0d 06 09 2a 86 48 86 f7 0d 01 01 0b 05 00 \
 30 1c 31 0e 30 0c 06 03 2a 03 04 13 05 68 65 6c 6c 6f 31 0a 30 08 06 03 \
 55 04 03 13 01 78 30 1e 17 0d 32 36 30 31 30 31 30 30 30 30 30 30 5a 17 \
 0d 32 37 30 31 30 31 30 30 30 30 30 30 5a 30 1c 31 0e 30 0c 06 03 2a 03 \
 04 13 05 68 65 6c 6c 6f 31 0a 30 08 06 03 55 04 03 13 01 78 30 1e 30 0d \
 06 09 2a 86 48 86 f7 0d 01 01 01 05 00 03 0d 00 30 0a 02 03 00 c1 23 02 \
 03 01 00 01 30 0d 06 09 2a 86 48 86 f7 0d 01 01 0b 05 00 03 05 00 de ad \
 be ef
agree      'hand-built v1 certificate parses'    "$T/hand.der"
certfields 'cert fields: hand-built v1, unknown attribute OID, 16-bit key' \
           "$T/hand.der"

# The same certificate with the commonName's value substituted, which is how
# the string conversions openssl applies before escaping get reached at all.
# The whole file is respelled per case rather than patched in place, because
# changing the value's length moves five enclosing lengths; respelling makes
# the arithmetic visible in one function instead of hidden in offsets.
#
# The 1.2.3.4 attribute stays in every one of these, so each case also
# re-checks the unknown-attribute hex dump.
#
# Two knobs: the commonName's value, as positional arguments, and the two Time
# elements, in $HC_TIME. HC_MOD is the RSA modulus INTEGER. Everything else is
# fixed.
HC_TIME='17 0d 32 36 30 31 30 31 30 30 30 30 30 30 5a
         17 0d 32 37 30 31 30 31 30 30 30 30 30 30 5a'
HC_MOD='02 03 00 c1 23'
# The extensions, as a run of complete Extension elements. Empty by default,
# which is also what makes the certificate v1 -- a version field appears only
# when there are extensions to require it.
HC_EXTS=''
# issuerUniqueID [1] and subjectUniqueID [2], both IMPLICIT BIT STRINGs. X.509
# v2 fields that RFC 5280 4.1.2.8 tells conforming CAs not to generate, so
# nothing in /etc/ssl/certs has one and openssl will not make one.
HC_UID=''
# The version field, overridable so a non-minimal encoding of it can be built.
HC_VERFIELD='a0 03 02 01 02'
# Set to 0 around a fixture that is deliberately not valid DER, so the
# template self-check below does not report the intended defect as a problem
# with the harness.
HC_CHECK=1

handcert() { # handcert FILE VALUEHEX...  -- rebuild with this commonName value
	_f=$1; shift
	_vn=$#
	# shellcheck disable=SC2086
	_tn=$(set -- $HC_TIME; echo $#)
	# shellcheck disable=SC2086
	_mn=$(set -- $HC_MOD; echo $#)
	# shellcheck disable=SC2086
	_en=$(set -- $HC_EXTS; echo $#)
	# shellcheck disable=SC2086
	_un=$(set -- $HC_UID; echo $#)
	if [ "$_en" -eq 0 ]; then
		_ver=''; _vern=0; _ext=''; _extn=0
	else
		_ver=$HC_VERFIELD
		# shellcheck disable=SC2086
		_vern=$(set -- $HC_VERFIELD; echo $#)
		_ext="a3 $(printf '%02x' $((_en + 2))) 30 $(printf '%02x' $_en) $HC_EXTS"
		_extn=$((_en + 4))
	fi
	# Name = SEQUENCE { SET{ 1.2.3.4=hello } (16), SET{ CN=value } (9+n) }
	_namec=$((16 + 9 + _vn))
	# SubjectPublicKeyInfo: SEQUENCE { AlgorithmIdentifier(15),
	# BIT STRING { SEQUENCE { modulus, exponent(5) } } }
	_keyc=$((_mn + 5))
	_spki=$((2 + 15 + 2 + 1 + 2 + _keyc))
	# TBS = version serial(3) sigalg(15) issuer validity subject spki exts
	_tbs=$((_vern + 3 + 15 + (_namec + 2) + (_tn + 2) + (_namec + 2) \
	        + _spki + _un + _extn))
	# TBS header is three bytes (30 81 xx) because _tbs is always above 127
	# here; outer sigalg is 15 and the signature 7.
	_all=$((_tbs + 3 + 15 + 7))
	# Both long-form lengths above are one byte, so the whole fixture has to
	# stay under 256. Said out loud rather than discovered as a parse error.
	[ "$_all" -le 255 ] || bad "handcert $_f" \
		"fixture is $_all bytes: too large for a one-byte long-form length"
	# shellcheck disable=SC2086
	der "$_f" 30 81 "$(printf '%02x' $_all)" \
	    30 81 "$(printf '%02x' $_tbs)" \
	    $_ver \
	    02 01 01 \
	    30 0d 06 09 2a 86 48 86 f7 0d 01 01 0b 05 00 \
	    30 "$(printf '%02x' $_namec)" \
	      31 0e 30 0c 06 03 2a 03 04 13 05 68 65 6c 6c 6f \
	      31 "$(printf '%02x' $((_vn + 7)))" \
	        30 "$(printf '%02x' $((_vn + 5)))" 06 03 55 04 03 "$@" \
	    30 "$(printf '%02x' $_tn)" $HC_TIME \
	    30 "$(printf '%02x' $_namec)" \
	      31 0e 30 0c 06 03 2a 03 04 13 05 68 65 6c 6c 6f \
	      31 "$(printf '%02x' $((_vn + 7)))" \
	        30 "$(printf '%02x' $((_vn + 5)))" 06 03 55 04 03 "$@" \
	    30 "$(printf '%02x' $((_spki - 2)))" \
	      30 0d 06 09 2a 86 48 86 f7 0d 01 01 01 05 00 \
	      03 "$(printf '%02x' $((_keyc + 3)))" 00 \
	        30 "$(printf '%02x' $_keyc)" $HC_MOD 02 03 01 00 01 \
	    $HC_UID \
	    $_ext \
	    30 0d 06 09 2a 86 48 86 f7 0d 01 01 0b 05 00 \
	    03 05 00 de ad be ef
	# A fixture nobody can read proves nothing, so the shape is checked
	# every time the arithmetic above is exercised with new sizes.
	[ "$HC_CHECK" -eq 0 ] || "$D" parse "$_f" >/dev/null 2>&1 \
	  || bad "handcert template for $_f" "derx cannot parse the fixture"
}

# PrintableString "caf" + 0xE9. openssl runs every one-byte-per-character
# type through MBSTRING_ASC, which treats the byte as a code point, so 0xE9
# becomes U+00E9 and prints as \C3\A9 -- Latin-1, not the type's own charset.
handcert "$T/h-printable.der" 13 04 63 61 66 e9
certfields 'cert fields: PrintableString with a high byte' "$T/h-printable.der"
# T61String 0xC1. In T.61 that is a combining acute accent; openssl makes it
# U+00C1, Latin-1 capital A-acute. The oracle decides, not the standard.
handcert "$T/h-t61.der" 14 02 c1 61
certfields 'cert fields: T61String byte 0xC1 is Latin-1, not T.61' "$T/h-t61.der"
# BMPString: UCS-2 big endian, converted to UTF-8 and then hex-escaped.
handcert "$T/h-bmp.der" 1e 06 00 68 00 69 00 e9
certfields 'cert fields: BMPString' "$T/h-bmp.der"
# UniversalString: UCS-4 big endian.
handcert "$T/h-univ.der" 1c 08 00 00 00 68 00 00 00 e9
certfields 'cert fields: UniversalString' "$T/h-univ.der"
# The escapes, one fixture each, all in a UTF8String.
handcert "$T/h-del.der"  0c 03 61 7f 62
certfields 'cert fields: 0x7F escapes as \7F'        "$T/h-del.der"
handcert "$T/h-nul.der"  0c 03 61 00 62
certfields 'cert fields: NUL escapes as \00'         "$T/h-nul.der"
handcert "$T/h-tab.der"  0c 03 61 09 62
certfields 'cert fields: tab escapes as \09'         "$T/h-tab.der"
handcert "$T/h-comma.der" 0c 03 61 2c 62
certfields 'cert fields: comma escapes as backslash' "$T/h-comma.der"
handcert "$T/h-plus.der" 0c 03 61 2b 62
certfields 'cert fields: plus escapes as backslash'  "$T/h-plus.der"
handcert "$T/h-eq.der"   0c 03 61 3d 62
certfields 'cert fields: equals does not escape'     "$T/h-eq.der"
handcert "$T/h-lead.der" 0c 03 20 61 20
certfields 'cert fields: leading and trailing space escape' "$T/h-lead.der"
handcert "$T/h-hash.der" 0c 03 23 61 23
certfields 'cert fields: leading # escapes, trailing # does not' "$T/h-hash.der"
handcert "$T/h-utf8.der" 0c 04 68 c3 a9 69
certfields 'cert fields: UTF8String high bytes escape individually' "$T/h-utf8.der"

# A UTF8String that is not valid UTF-8, and a BMPString of odd length.
# openssl refuses the whole certificate for both, so these are reject cases
# for `derx cert` rather than comparisons -- and the assertion includes
# openssl's refusal, so "we agree it is unreadable" is measured.
certreject() { # certreject NAME FILE
	_n=$1; _f=$2
	"$D" cert "$_f" >/dev/null 2>"$T/d.err"; _ds=$?
	openssl x509 -in "$_f" -inform DER -noout -subject >/dev/null 2>&1; _os=$?
	if [ "$_ds" -ne 1 ]; then
		bad "$_n" "want derx exit 1, got $_ds" "$(cat "$T/d.err")"
	elif ! grep -q '^derx: ' "$T/d.err"; then
		bad "$_n" "exit 1 but no 'derx: ' diagnostic"
	elif [ "$_os" -eq 0 ]; then
		bad "$_n" "openssl accepted it, so refusing is ours alone"
	else
		ok "$_n"
	fi
}
handcert "$T/h-badutf8.der" 0c 03 61 ff 62
certreject 'cert: invalid UTF-8 in a UTF8String' "$T/h-badutf8.der"
handcert "$T/h-oddbmp.der" 1e 03 00 61 00
certreject 'cert: BMPString of odd length' "$T/h-oddbmp.der"
handcert "$T/h-surrogate.der" 1e 04 d8 00 dc 00
certreject 'cert: BMPString containing a surrogate' "$T/h-surrogate.der"
handcert "$T/h-overlong.der" 0c 02 c0 af
certreject 'cert: overlong UTF-8 encoding' "$T/h-overlong.der"
# Attribute values that are not string types. openssl's X509_NAME template
# draws its line in an odd place -- its ASN1_PRINTABLE mask takes BIT STRING
# and SEQUENCE and dumps them as hex, but refuses INTEGER and VisibleString
# and then declines to read the certificate at all. derx draws a narrower
# line: anything it cannot render as text is refused. So two of these four
# are shared judgements and two are derx being stricter, and the suite says
# which is which rather than averaging them.
handcert "$T/h-intval.der" 02 01 2a
certreject 'cert: INTEGER as an attribute value, refused by both' "$T/h-intval.der"
handcert "$T/h-visval.der" 1a 03 61 62 63
certreject 'cert: VisibleString attribute value, refused by both' "$T/h-visval.der"

certstricter() { # certstricter NAME FILE -- openssl reads it, derx will not
	_n=$1; _f=$2
	"$D" cert "$_f" >/dev/null 2>"$T/d.err"; _ds=$?
	openssl x509 -in "$_f" -inform DER -noout -subject >/dev/null 2>&1; _os=$?
	if [ "$_ds" -ne 1 ]; then
		bad "$_n" "want derx exit 1, got $_ds" "$(cat "$T/d.err")"
	elif ! grep -q '^derx: ' "$T/d.err"; then
		bad "$_n" "exit 1 but no 'derx: ' diagnostic"
	elif [ "$_os" -ne 0 ]; then
		bad "$_n" "openssl refused it too, so this is not a divergence"
	else
		ok "$_n"
	fi
}
handcert "$T/h-seqval.der" 30 02 05 00
certstricter 'cert: SEQUENCE attribute value, openssl dumps it and derx will not' \
	"$T/h-seqval.der"
handcert "$T/h-bitval.der" 03 02 00 07
certstricter 'cert: BIT STRING attribute value, openssl dumps it and derx will not' \
	"$T/h-bitval.der"

# ---------------------------------------------------------------------------
# The two-digit year, and the two time encodings. RFC 5280 4.1.2.5 splits the
# century at 2050: 50 through 99 mean 19xx and 00 through 49 mean 20xx. Only a
# certificate dated exactly at the boundary can tell the right pivot from one
# that is off by one, and no generated fixture lands there -- openssl's own
# req would emit a GeneralizedTime for anything past 2049.
# ---------------------------------------------------------------------------
HC_TIME='17 0d 34 39 30 31 30 31 30 30 30 30 30 30 5a
         17 0d 35 30 30 31 30 31 30 30 30 30 30 30 5a'
handcert "$T/h-pivot.der" 13 01 78
certfields 'cert fields: UTCTime 49 is 2049 and 50 is 1950' "$T/h-pivot.der"
# GeneralizedTime in both positions, and then one of each, which is a shape a
# real certificate issued near 2050 will have.
HC_TIME='18 0f 32 30 34 39 30 31 30 31 30 30 30 30 30 30 5a
         18 0f 32 30 35 31 30 31 30 31 30 30 30 30 30 30 5a'
handcert "$T/h-gen.der" 13 01 78
certfields 'cert fields: GeneralizedTime in both positions' "$T/h-gen.der"
HC_TIME='17 0d 34 39 31 32 33 31 32 33 35 39 35 39 5a
         18 0f 32 30 35 30 30 31 30 31 30 30 30 30 30 30 5a'
handcert "$T/h-mixed.der" 13 01 78
certfields 'cert fields: UTCTime notBefore, GeneralizedTime notAfter' \
	"$T/h-mixed.der"
# A UTCTime with no seconds. X.680 allows that form; RFC 5280 4.1.2.5 does not,
# and openssl turns out to agree -- it refuses the certificate outright rather
# than defaulting the seconds to zero. Asserted as a shared refusal, which is
# where it belongs; it was written as a derx-is-stricter case and the oracle
# said otherwise.
HC_TIME='17 0b 32 36 30 31 30 31 30 30 30 30 5a
         17 0d 32 37 30 31 30 31 30 30 30 30 30 30 5a'
handcert "$T/h-nosec.der" 13 01 78
certreject 'cert: UTCTime without seconds, refused by both' "$T/h-nosec.der"
HC_TIME='17 0d 32 36 30 31 30 31 30 30 30 30 30 30 5a
         17 0d 32 37 30 31 30 31 30 30 30 30 30 30 5a'

# ---------------------------------------------------------------------------
# A modulus with a redundant leading zero byte. openssl ignores the padding
# and still says 16 bit; derx refuses the INTEGER, because X.690 8.3.2 applies
# in `derx cert` exactly as it does in `derx parse`.
#
# This fixture exists because of a mutation that survived without it: deleting
# the leading-zero scan from int_bits() changed nothing, since a *minimal*
# modulus has at most one pad byte and the two calculations agree there. With
# a second pad byte they disagree -- and with the INTEGER check shared, they
# cannot disagree on anything derx will read, which makes the mutation
# provably equivalent rather than merely untested.
# ---------------------------------------------------------------------------
HC_MOD='02 04 00 00 c1 23'
handcert "$T/h-padmod.der" 13 01 78
certstricter 'cert: modulus with two leading zero bytes' "$T/h-padmod.der"
# A one-byte modulus, so the bit length is counted inside a single byte.
HC_MOD='02 01 7f'
handcert "$T/h-tinymod.der" 13 01 78
certfields 'cert fields: a 7-bit RSA modulus' "$T/h-tinymod.der"
HC_MOD='02 02 00 80'
handcert "$T/h-8bitmod.der" 13 01 78
certfields 'cert fields: an 8-bit RSA modulus needing a sign pad' "$T/h-8bitmod.der"
HC_MOD='02 03 00 c1 23'

# ---------------------------------------------------------------------------
# Extensions, hand-built, because openssl's generator cannot be made to emit
# any of these either.
#
# The first is the one that matters. A key usage BIT STRING declaring one
# unused bit, with that bit set to one: 03 02 01 87. openssl's
# ossl_c2i_ASN1_BIT_STRING masks the unused bits to zero as it parses, so it
# reports bits 0, 5 and 6 and not bit 7 -- and without this fixture, deleting
# the unused-bit arithmetic from derx's key usage decoder changed nothing,
# because every other key usage in the suite has its padding bits already
# zero. The mutation survived; this kills it.
# ---------------------------------------------------------------------------
HC_EXTS='30 0b 06 03 55 1d 0f 04 04 03 02 01 87'
handcert "$T/h-kupad.der" 13 01 78
certfields 'cert fields: key usage with a nonzero unused bit' "$T/h-kupad.der"
certexts   'cert extensions: unused bits are masked, not reported' "$T/h-kupad.der"
# All nine key usage bits, which needs two value octets and seven unused bits.
HC_EXTS='30 0c 06 03 55 1d 0f 04 05 03 03 07 ff 80'
handcert "$T/h-ku9.der" 13 01 78
certexts 'cert extensions: all nine key usage bits' "$T/h-ku9.der"
# critical TRUE on an extension, spelled out rather than left to openssl.
HC_EXTS='30 0e 06 03 55 1d 0f 01 01 ff 04 04 03 02 01 86'
handcert "$T/h-kucrit.der" 13 01 78
certfields 'cert fields: critical flag on key usage' "$T/h-kucrit.der"
certexts   'cert extensions: critical key usage' "$T/h-kucrit.der"
# critical FALSE encoded explicitly. DER says the DEFAULT value must be
# omitted, so this is a second encoding of "not critical" and derx refuses it.
HC_EXTS='30 0e 06 03 55 1d 0f 01 01 00 04 04 03 02 01 86'
handcert "$T/h-kucritfalse.der" 13 01 78
certstricter 'cert: critical FALSE encoded explicitly, which DER forbids' \
	"$T/h-kucritfalse.der"
# An extension OID openssl has no name for: both sides print it dotted, and
# derx marks the value as one it does not decode.
HC_EXTS='30 0d 06 04 2a 03 04 05 04 05 30 03 01 01 ff'
handcert "$T/h-extunknown.der" 13 01 78
certfields 'cert fields: an extension openssl cannot name either' \
	"$T/h-extunknown.der"
HC_EXTS=''

# The two obsolete unique identifiers, which derx skips rather than prints.
# Nothing else in the suite reaches that loop: deleting it left every
# assertion green until this fixture existed.
HC_UID='81 02 00 07 82 02 00 03'
HC_EXTS='30 0b 06 03 55 1d 0f 04 04 03 02 01 86'
handcert "$T/h-uid.der" 13 01 78
certfields 'cert fields: issuerUniqueID and subjectUniqueID are skipped' \
	"$T/h-uid.der"
certexts   'cert extensions: an extension after both unique IDs' "$T/h-uid.der"
HC_UID=''

# ---------------------------------------------------------------------------
# Six places where an element carries more than the structure allows. All of
# them exist because a mutation survived without them: deleting the
# "unexpected trailing bytes" check from the cursor's rd_end() left every
# assertion green, since nothing in the suite had any trailing bytes anywhere.
#
# openssl refuses five of the six outright -- its template-driven decoder is
# exact about how many components a SEQUENCE has -- so those are shared
# judgements. The sixth, a NULL sitting after the whole certificate, openssl
# reads happily, taking the first object in the file and ignoring the rest.
# ---------------------------------------------------------------------------
HC_EXTS='30 0d 06 03 55 1d 0f 04 04 03 02 01 86 05 00'
handcert "$T/h-exttrail.der" 13 01 78
certreject 'cert: a NULL after an extension value, refused by both' \
	"$T/h-exttrail.der"
HC_EXTS='30 0b 06 03 55 1d 0f 04 04 03 02 01 86'
# A non-minimal version INTEGER: 02 02 00 02 instead of 02 01 02.
HC_VERFIELD='a0 04 02 02 00 02'
HC_CHECK=0
handcert "$T/h-vernonmin.der" 13 01 78
HC_CHECK=1
certreject 'cert: non-minimal version INTEGER, refused by both' \
	"$T/h-vernonmin.der"
# A second INTEGER inside the version field.
HC_VERFIELD='a0 06 02 01 02 02 01 02'
handcert "$T/h-vertwo.der" 13 01 78
certreject 'cert: two INTEGERs in the version field, refused by both' \
	"$T/h-vertwo.der"
HC_VERFIELD='a0 03 02 01 02'
HC_EXTS=''
# A third Time in the validity SEQUENCE.
HC_TIME='17 0d 32 36 30 31 30 31 30 30 30 30 30 30 5a
         17 0d 32 37 30 31 30 31 30 30 30 30 30 30 5a
         17 0d 32 38 30 31 30 31 30 30 30 30 30 30 5a'
handcert "$T/h-threetimes.der" 13 01 78
certreject 'cert: three timestamps in the validity SEQUENCE, refused by both' \
	"$T/h-threetimes.der"
HC_TIME='17 0d 32 36 30 31 30 31 30 30 30 30 30 30 5a
         17 0d 32 37 30 31 30 31 30 30 30 30 30 30 5a'
# A third element in an attribute: OID, value, and then a NULL.
handcert "$T/h-atvtrail.der" 13 01 78 05 00
certreject 'cert: a NULL after an attribute value, refused by both' \
	"$T/h-atvtrail.der"
# And bytes after the certificate itself.
handcert "$T/h-base.der" 13 01 78
cat "$T/h-base.der" > "$T/h-after.der"
der "$T/nullel" 05 00
cat "$T/nullel" >> "$T/h-after.der"
certstricter 'cert: a NULL after the certificate' "$T/h-after.der"

# `derx cert` on things that are DER but are not certificates.
for f in csr rsakey pkcs8 eckey ecparam; do
	if [ ! -f "$T/$f.der" ]; then
		skipt "cert: refuses a $f, which is DER but not a certificate" \
		      'the fixture was not generated'
		continue
	fi
	"$D" cert "$T/$f.der" >/dev/null 2>"$T/d.err"; s=$?
	if [ "$s" -eq 1 ] && grep -q '^derx: ' "$T/d.err"; then
		ok "cert: refuses a $f, which is DER but not a certificate"
	else
		bad "cert: refuses a $f, which is DER but not a certificate" \
		    "exit $s" "$(cat "$T/d.err")"
	fi
done

# ---------------------------------------------------------------------------
# The whole trust store through `derx cert`.
# ---------------------------------------------------------------------------
if [ "$ncert" -ge 100 ]; then
	fbad=0; ffirst=''; fcnt=0
	for f in "$T"/corpus/*.der; do
		"$D" cert "$f" > "$T/d.all" 2>/dev/null || { fbad=$((fbad + 1))
			[ -n "$ffirst" ] || ffirst="$f (derx cert failed)"; continue; }
		grep -v '^ext=' "$T/d.all" > "$T/d.out"
		oracle_fields "$f" > "$T/o.out"
		sed -E -n 's/^ext=([^:]*:(critical|-)):.*/ext=\1/p' "$T/d.all" > "$T/d.ext"
		oracle_extnames "$T/txt" > "$T/o.ext"
		if cmp -s "$T/d.out" "$T/o.out" && cmp -s "$T/d.ext" "$T/o.ext"; then
			fcnt=$((fcnt + 1))
		else
			fbad=$((fbad + 1))
			if [ -z "$ffirst" ]; then
				ffirst=$f
				cp "$T/d.out" "$T/f-derx"; cp "$T/o.out" "$T/f-ssl"
				cat "$T/d.ext" >> "$T/f-derx"; cat "$T/o.ext" >> "$T/f-ssl"
			fi
		fi
	done
	if [ "$fcnt" -lt 100 ]; then
		bad 'cert fields: the whole trust store' \
		    "only $fcnt certificates compared, $fbad failed"
	elif [ "$fbad" -ne 0 ]; then
		bad 'cert fields: the whole trust store' "first failure: $ffirst" \
		    "$(diff "$T/f-ssl" "$T/f-derx" 2>/dev/null | head -12)"
	else
		ok "cert fields: $fcnt certificates, 9 fields and every extension name"
	fi

	# Extension values across the corpus. Here, unlike the fixtures,
	# declining is allowed -- 5 of these certificates have an authority key
	# identifier carrying an issuer name and serial, which openssl prints
	# on three lines and this one-line format cannot hold, and one has a
	# DirName in its subjectAltName. So both numbers are asserted: the
	# agreements have to be in the hundreds and the declines in single
	# figures, because a derx that answered "?" to everything would
	# otherwise pass this group while failing nothing.
	eagree=0; edecline=0; ewrong=0; efirst=''
	for f in "$T"/corpus/*.der; do
		"$D" cert "$f" > "$T/d.all" 2>/dev/null || continue
		for sn in $EXTSN; do
			o=$(oracle_ext "$f" "$sn"); st=$?
			[ "$st" -eq 1 ] && continue
			if [ "$st" -eq 2 ]; then
				# openssl needed several lines; derx must have
				# declined rather than invented a one-liner.
				# That sentence used to describe a check that
				# was not here: edecline was incremented
				# unconditionally and derx's answer never read,
				# so a derx that invented a value for exactly
				# these extensions would have been counted as
				# having declined. The name comes from
				# openssl's own first line in $T/e.txt, which
				# oracle_ext has already written -- the old
				# $n2 took the first ext line of derx's output
				# regardless of which extension it belonged
				# to, and was then never used at all.
				n2=$(sed -n '1{s/: critical$//;s/: *$//;p;}' "$T/e.txt")
				d2=$(grep "^ext=$n2:" "$T/d.all")
				case $d2 in
				''|*:'?') edecline=$((edecline + 1))
				   eval "dc_$sn=\$((dc_$sn + 1))" ;;
				*) ewrong=$((ewrong + 1))
				   [ -n "$efirst" ] || efirst="$f $n2: openssl needed several lines, derx answered [$d2]" ;;
				esac
				continue
			fi
			name=${o%%:*}
			d=$(grep "^ext=$name:" "$T/d.all")
			# Only one comparison here: the second arm used to be
			# `[ "$d" = "ext=$name:${o#*:}" ]`, which rebuilds the
			# very string the first arm already tested -- $o is
			# "$name:$rest", so "ext=$o" and "ext=$name:${o#*:}"
			# are the same characters. It could never be reached.
			if [ "ext=$o" = "$d" ]; then
				eagree=$((eagree + 1))
				eval "ag_$sn=\$((ag_$sn + 1))"
			else
				case $d in
				*:'?') edecline=$((edecline + 1))
				   eval "dc_$sn=\$((dc_$sn + 1))" ;;
				*) ewrong=$((ewrong + 1))
				   [ -n "$efirst" ] || efirst="$f $sn: oracle [ext=$o] derx [$d]" ;;
				esac
			fi
		done
	done
	if [ "$ewrong" -ne 0 ]; then
		bad 'cert extension values across the trust store' \
		    "$ewrong disagreements, $eagree agreements, $edecline declined" \
		    "$efirst"
	else
		# This line claims one thing only: nothing disagreed. It used to
		# carry the thresholds too, and when those moved to the
		# per-extension block below it was briefly left saying
		# "ok cert extension values: 328 agree, 155 declined" about a
		# derx with its subject key identifier decoder deleted. The
		# counts belong in the table below, next to the floors that
		# judge them.
		ok "cert extension values: $((eagree + edecline)) compared, $ewrong disagreed with openssl"
	fi
fi

# ---------------------------------------------------------------------------
# The same six extensions, counted one at a time.
#
# What this replaces was a floor of two agreements per certificate and a
# ceiling of twenty declines over the whole group. Both held, and neither
# could see which of the six extensions was being exercised: an extension with
# three cases and one with three thousand both read as "agrees", and the total
# tracks whichever is largest. The first run of the per-extension count found
# extendedKeyUsage at 0 agreements and 0 declines over the entire trust store,
# because a CA root does not carry one, and its whole coverage anywhere in
# this suite is the single generated leaf fixture. The aggregate 477 said
# nothing about that and could not have.
#
# Measured over the 150 certificates in /etc/ssl/certs and the 22 fixtures
# that carry a supported extension:
#
#   extension                 agree  decline  per cert  floor      fixtures
#   basicConstraints            150        0     1.000  ncert*4/5        16
#   keyUsage                    147        0     0.980  ncert*4/5         6
#   extendedKeyUsage              0        0     0.000  0                 1
#   subjectKeyIdentifier        149        0     0.993  ncert*4/5        16
#   authorityKeyIdentifier       29        5     0.193  ncert/10         16
#   subjectAltName                2        1     0.013  1                 1
#
# The trust-store floors are fractions of $ncert rather than the measured
# numbers because the check above deliberately accepts a store of as few as
# 100 certificates, and a floor of 150 would call a thinned store a broken
# derx. 4/5 of ncert sits under the lowest of the three near-universal rates
# (0.980) with room for a store carrying a few more exceptions than this one;
# ncert/10 is half the measured authorityKeyIdentifier rate.
#
# subjectAltName's floor is 1, the honest minimum: below 1 the extension is
# not exercised by this group at all. Its 2 agreements are the whole of its
# trust-store coverage and it is meant to go red if the store stops carrying
# a leaf certificate.
#
# extendedKeyUsage is floored at 0 here and at its exact fixture count below.
# A floor of 1 on the trust store would be a floor that has never been met,
# and raising the corpus to meet it means putting a leaf certificate in
# /etc/ssl/certs, which is not ours to edit.
# ---------------------------------------------------------------------------
# The fixture counts are exact. These inputs are built by this file: openssl's
# generator makes ext-san, ext-ku and ext-leaf, and the hand-built templates
# make the key usage cases. Nothing outside the repository can move them, so a
# floor would be weaker than an equality for no gain, and any edit that drops
# a fixture has to come here and say so.
fxexp_basicConstraints=16
fxexp_keyUsage=6
fxexp_extendedKeyUsage=1
fxexp_subjectKeyIdentifier=16
fxexp_authorityKeyIdentifier=16
fxexp_subjectAltName=1

ebad=''
# Six, counted, not assumed. A per-extension check that iterates $EXTSN cannot
# see a name deleted from $EXTSN: the row disappears along with its floor.
# Deleting keyUsage from the list was tried, and this group reported "330
# agree, 6 declined" and passed, because the old aggregate floor was two
# agreements per certificate and 330 clears 300 comfortably. The four key
# usage fixtures did fail, through certexts' vacuity guard, so the suite went
# red, but nothing anywhere said that an extension's oracle had stopped
# running. This line does.
# shellcheck disable=SC2086
enames=$(set -- $EXTSN; echo $#)
if [ "$enames" -ne 6 ]; then
	bad 'per-extension counts' \
	    "EXTSN names $enames extensions, not the 6 derx decodes:" \
	    "a name removed from the list removes its floor with it"
fi
for sn in $EXTSN; do
	eval "a=\$ag_$sn; d=\$dc_$sn; x=\$fx_$sn; e=\$fxexp_$sn"
	# The fixture equality is checked either way; the trust-store floors
	# only when the trust-store group ran at all. Without this, an absent
	# /etc/ssl/certs would report six floor failures underneath the one
	# assertion that already says the store is missing, and the real
	# message would be the hardest of the seven to find.
	if [ "$ncert" -lt 100 ]; then
		[ "$x" -eq "$e" ] || ebad="$ebad
$sn: $x fixture agreements, expected exactly $e"
		continue
	fi
	case $sn in
	basicConstraints|keyUsage|subjectKeyIdentifier) amin=$((ncert * 4 / 5)) ;;
	authorityKeyIdentifier)                         amin=$((ncert / 10)) ;;
	subjectAltName)                                 amin=1 ;;
	extendedKeyUsage)                               amin=0 ;;
	esac
	# Only two of the six can decline at all. authorityKeyIdentifier's
	# issuer-name-and-serial form and a subjectAltName carrying a
	# directoryName are values openssl prints on several lines and this
	# one-line format cannot hold, so "?" is the right answer and is
	# counted. The other four have no such form: a "?" from any of them is
	# derx failing to decode something it claims to decode, and exactly
	# zero is the only acceptable number. The old aggregate ceiling of 20
	# could not say that -- fourteen keyUsage values quietly turning into
	# "?" passed it.
	case $sn in
	authorityKeyIdentifier) dmax=$((ncert / 10)) ;;
	subjectAltName)         dmax=$((ncert / 30)) ;;
	*)                      dmax=0 ;;
	esac
	printf '      %-24s trust store: %3d agree, %d declined (floor %d, %d)  fixtures: %d\n' \
	    "$sn" "$a" "$d" "$amin" "$dmax" "$x"
	[ "$a" -ge "$amin" ] || ebad="$ebad
$sn: $a agreements over $ncert certificates, floor $amin"
	[ "$d" -le "$dmax" ] || ebad="$ebad
$sn: $d declined, ceiling $dmax"
	[ "$x" -eq "$e" ] || ebad="$ebad
$sn: $x fixture agreements, expected exactly $e"
done
if [ -n "$ebad" ]; then
	bad 'per-extension counts' "$ebad"
else
	ok 'per-extension counts: six extensions, each above its own floor'
fi

# ===========================================================================
# 7. malformed input: both programs refuse
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
# 8. valid BER that is not valid DER: openssl accepts, derx refuses
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
# 9. the half openssl cannot judge: derx never crashes
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

# ===========================================================================
# 9b. the differential fuzzer
# ===========================================================================
# The two sweeps above are systematic but shallow: one certificate, one byte
# at a time, and almost every result is refused by both programs before any
# value is printed. t/fuzz.py mutates the whole corpus instead, and three of
# its eight mutators keep the framing intact, so most of its mutants are
# valid DER files that say something strange and both programs parse them.
# That is where the comparison happens, so the run asserts a floor on how
# many mutants reached one: "0 differences" over inputs nobody could parse
# is a vacuous pass, and the floor is what makes it impossible here.
#
# Fixed seed, no wall clock: a failure here reproduces exactly, and the
# fuzzer writes the bytes out as well. Its scratch is its own mkdtemp, not
# $T, so a longer run started by hand does not collide with this one.
if command -v python3 >/dev/null 2>&1; then
	if python3 "$ROOT/t/fuzz.py" --derx "$D" --seed 1 --count 600 \
	     --min-compared 250 --quiet "$T"/corpus/*.der "$T"/*.der \
	     > "$T/fuzz.log" 2>&1; then
		ok "differential fuzzer, 600 mutants"
		sed 's/^/      | /' "$T/fuzz.log"
	else
		bad 'differential fuzzer, 600 mutants' "$(cat "$T/fuzz.log")"
	fi
	# Determinism is what makes a failure here worth having: the seed is
	# the only entropy, mutant i is a pure function of (seed, i), and that
	# is the promise behind "reproduce with --start i --count 1". --digest
	# prints the bytes' SHA-256 without running either program, so the
	# three claims below are checked exactly rather than through their
	# effect on a summary line.
	#
	# The first version of this compared two whole fuzzer logs, and it
	# passed with --seed deliberately ignored: the logs differ on the
	# line that echoes the seed back, so cmp saw a difference and never
	# looked at the mutants. That assertion was checking its own echo.
	python3 "$ROOT/t/fuzz.py" --seed 2 --start 0 --count 40 --digest \
	    "$T"/corpus/*.der > "$T/f2.dig" 2>&1
	python3 "$ROOT/t/fuzz.py" --seed 2 --start 30 --count 10 --digest \
	    "$T"/corpus/*.der > "$T/f2tail.dig" 2>&1
	python3 "$ROOT/t/fuzz.py" --seed 3 --start 0 --count 40 --digest \
	    "$T"/corpus/*.der > "$T/f3.dig" 2>&1
	tail -10 "$T/f2.dig" > "$T/f2last.dig"
	if [ "$(wc -l < "$T/f2.dig")" -ne 40 ]; then
		bad 'fuzzer: mutant i is a pure function of (seed, i)' \
		    "--digest printed $(wc -l < "$T/f2.dig") lines, wanted 40"
	elif ! cmp -s "$T/f2last.dig" "$T/f2tail.dig"; then
		bad 'fuzzer: mutant i is a pure function of (seed, i)' \
		    "--start 30 --count 10 is not the tail of --count 40:" \
		    "a saved failure would not replay" \
		    "$(diff "$T/f2last.dig" "$T/f2tail.dig" | head -6)"
	elif cmp -s "$T/f2.dig" "$T/f3.dig"; then
		bad 'fuzzer: mutant i is a pure function of (seed, i)' \
		    'seeds 2 and 3 produced the same 40 mutants: --seed is not wired up'
	else
		ok 'fuzzer: mutant i is a pure function of (seed, i)'
	fi
else
	skipt 'differential fuzzer' 'python3 not found'
	skipt 'fuzzer: mutant i is a pure function of (seed, i)' 'python3 not found'
fi

# ===========================================================================
# 10. the command line itself
# ===========================================================================
# Exit 2 is reserved for "derx was invoked wrongly" and must stay distinct
# from exit 1, "the input was not DER". A suite that asserted only "nonzero"
# would not notice the two merging.
cli() { # cli NAME WANT_STATUS -- ARGS...
	_n=$1; _w=$2; shift 3
	"$D" "$@" >/dev/null 2>"$T/c.err"; _s=$?
	if [ "$_s" -eq "$_w" ]; then ok "$_n"
	else bad "$_n" "want exit $_w, got $_s" "$(cat "$T/c.err")"; fi
}
cli 'no arguments is a usage error'        2 -- 
cli 'one argument is a usage error'        2 -- parse
cli 'three arguments is a usage error'     2 -- parse a b
# Reported as an unknown subcommand, not as a file that would not open: the
# file is deliberately not touched until the subcommand is known good.
cli 'unknown subcommand is a usage error'  2 -- frobnicate "$T/h-base.der"
cli 'unreadable file is not a usage error' 1 -- parse /nonexistent-derx-xyz
cli 'unreadable file for cert'             1 -- cert  /nonexistent-derx-xyz

# A FILE of "-" is stdin, for either subcommand. Checked by comparing against
# the same file read by name, which is the only thing that could differ.
"$D" parse "$T/h-base.der" > "$T/byname.out" 2>&1
"$D" parse - < "$T/h-base.der" > "$T/bystdin.out" 2>&1
if [ -s "$T/byname.out" ] && cmp -s "$T/byname.out" "$T/bystdin.out"; then
	ok 'parse reads stdin when FILE is -'
else
	bad 'parse reads stdin when FILE is -' "$(diff "$T/byname.out" "$T/bystdin.out")"
fi
"$D" cert "$T/h-base.der" > "$T/byname.out" 2>&1
"$D" cert - < "$T/h-base.der" > "$T/bystdin.out" 2>&1
if [ -s "$T/byname.out" ] && cmp -s "$T/byname.out" "$T/bystdin.out"; then
	ok 'cert reads stdin when FILE is -'
else
	bad 'cert reads stdin when FILE is -' "$(diff "$T/byname.out" "$T/bystdin.out")"
fi
# Stdin is read with fread in a loop, so a pipe that delivers the file in
# small pieces must produce the same thing as one that does not.
dd if="$T/h-base.der" bs=1 2>/dev/null | "$D" parse - > "$T/bypipe.out" 2>&1
"$D" parse "$T/h-base.der" > "$T/byname.out" 2>&1
if cmp -s "$T/byname.out" "$T/bypipe.out"; then
	ok 'stdin arriving one byte at a time reads the same'
else
	bad 'stdin arriving one byte at a time reads the same' \
	    "$(diff "$T/byname.out" "$T/bypipe.out")"
fi

# ===========================================================================
# 11. the harness's own failure paths
# ===========================================================================
# Every assertion in this file is a function that can report a pass or a
# failure, and a check that has never been seen to report a failure may be
# checking nothing. These run the harness itself against inputs chosen to
# make it fail, and assert that it does. `guard` runs an assertion in a
# subshell, so its counters cannot reach the ones here, and requires its
# output to begin with FAIL.
#
# This is the half of the planned harness mutation sweep that belongs in the
# suite rather than in a record of one afternoon. Each guard below was
# watched to go red by deleting the check it covers, and the check it covers
# is named beside it.
guard() { # guard NAME ASSERTION ARGS... -- the assertion must report a failure
	_gn=$1; shift
	_gout=$("$@" 2>&1)
	case $_gout in
	FAIL*) ok "harness: $_gn" ;;
	*) bad "harness: $_gn" 'the assertion did not fail. It printed:' "$_gout" ;;
	esac
}

# agree() must notice a differing value. secp192k1 is an OID openssl names
# and derx prints in dotted form, which is the one disagreement this suite
# can produce on demand: the missing-name gap the fuzzer counts, as a
# fixture. Covers the cmp. If the OID table ever grows out of openssl's
# objects.txt this needs another OID openssl knows and derx does not.
openssl asn1parse -genstr OID:1.3.132.0.31 -out "$T/g-name.der" -noout 2>/dev/null
guard 'agree fails on a differing OBJECT value' agree 'probe' "$T/g-name.der"
# And must not read a shared refusal as an agreement. The input is the empty
# file because it is the only one here that makes the comparison genuinely
# vacuous: openssl prints "Error in encoding" on stdout for most of what it
# refuses, so for a truncated element the diff fails on its own and says
# nothing about agree()'s guards. On the empty file both programs print
# nothing at all, and with the three status and line-count checks deleted
# together agree() compares two empty files and reports a pass. Measured: any
# one or two of the three can go without changing a verdict, and all three
# together turn that probe green, which is what this guard is for.
: > "$T/g-none.der"
der "$T/g-short.der" 04 03 61 62
guard 'agree fails when both programs refuse the input' agree 'probe' "$T/g-none.der"
# reject() must notice derx accepting what was called malformed.
der "$T/g-null.der" 05 00
guard 'reject fails when derx accepts the input' reject 'probe' "$T/g-null.der"
# And must notice the oracle's verdict. This file is BER that openssl reads,
# so asserting it as a shared refusal has to fail: that check is the whole
# difference between `reject` and `stricter`, and without it "openssl agrees
# this is not DER" and "openssl reads it happily" are the same assertion.
der "$T/g-ber.der" 04 81 05 68 65 6c 6c 6f
guard 'reject fails when openssl accepts what is claimed as shared' \
	reject 'probe' "$T/g-ber.der"
# The same two directions for `derx cert`. h-after.der is a certificate with
# a NULL after it, which openssl reads and derx refuses; h-nosec.der has a
# UTCTime with no seconds, which both refuse.
guard 'certreject fails when openssl accepts the certificate' \
	certreject 'probe' "$T/h-after.der"
guard 'certstricter fails when openssl refuses it too' \
	certstricter 'probe' "$T/h-nosec.der"
# certexts() must not pass over a certificate carrying none of the six
# extensions it compares. h-base.der is the hand-built v1, which has no
# extensions at all.
guard 'certexts fails when no extension was compared' \
	certexts 'probe' "$T/h-base.der"
# sweep() the same, over a directory with nothing in it.
mkdir -p "$T/g-empty"
guard 'sweep fails on an empty directory' sweep 'probe' "$T/g-empty"

# Three checks are about how the program under test behaves rather than about
# any input, so no file can make them fail: that a refusal carries a
# diagnostic, that exit 1 and exit 2 stay apart, and that the sweeps call
# anything above 2 a defect. A mutation sweep over this file left all three
# alive for that reason. They are falsifiable against a program that does
# the wrong thing, so these three run the harness against a stub that is not
# derx, named so nothing here can be read as an assertion about derx.
with_stub() { # with_stub STUB ASSERTION ARGS... -- $D is the stub, in a subshell
	D=$1; shift; "$@"
}
printf '#!/bin/sh\nexit 1\n' > "$T/g-quiet"
printf '#!/bin/sh\necho "derx: refused" >&2\nexit 2\n' > "$T/g-exit2"
printf '#!/bin/sh\nexit 86\n' > "$T/g-abort"
chmod +x "$T/g-quiet" "$T/g-exit2" "$T/g-abort"
guard 'reject fails on a refusal with no diagnostic' \
	with_stub "$T/g-quiet" reject 'probe' "$T/g-short.der"
# Exit 2 is "derx was invoked wrongly" and must never be read as "the input
# was refused", which is the three-valued status the whole reject group rests
# on. The stub prints a diagnostic, so only the status can fail it.
guard 'reject fails on exit 2 where it wants exit 1' \
	with_stub "$T/g-exit2" reject 'probe' "$T/g-short.der"
# 86 is the sanitizer abort. Under `make test-asan` that is the difference
# between a clean refusal and a heap overflow, and the sweeps are the only
# thing that looks at it.
mkdir -p "$T/g-two"; cp "$T/g-null.der" "$T/g-two/a"; cp "$T/g-null.der" "$T/g-two/b"
guard 'sweep fails on a status above 2' \
	with_stub "$T/g-abort" sweep 'probe' "$T/g-two"

# ===========================================================================
# 12. what this file itself ran
# ===========================================================================
# A block of assertions that stops running leaves nothing behind but a
# smaller number. Breaking the sed that reads the OID table out of derx.c on
# purpose took 69 assertions away and the run reported "219 passed, 0
# failed": green, with nothing in the output saying that a group had stopped.
#
# So the count is asserted against a literal. It is a constant wherever this
# suite can be green at all: every input is either built here or counted as a
# skip when openssl's generator refuses it, and the trust-store groups add
# assertions per group rather than per certificate, so a store of 100
# certificates runs the same assertions as one of 150. Adding an assertion
# means editing the number here, which is the point -- the README quotes it.
#
# The element total cannot be a literal the same way, since 9,627 of the
# 10,891 come from whatever /etc/ssl/certs holds. The fixtures' share can:
# it is $elements less the trust store's $celem, and a floor on that catches
# agree() quietly stopping counting, which the total cannot, because the
# trust store's 9,627 would still clear any floor worth setting.
_ran=$((pass + fail + skip))
if [ "$_ran" -ne 331 ]; then
	bad 'every assertion this file contains ran' \
	    "$_ran assertions above this line, expected 331" \
	    'a group that stopped running is invisible in any other way'
else
	ok "assertions: $_ran above this line, the number this file expects"
fi
_fxel=$((elements - celem))
if [ "$_fxel" -lt 1000 ]; then
	bad 'the fixtures reached a byte-for-byte comparison' \
	    "$_fxel elements outside the trust store, floor 1000" \
	    "(total $elements, of which $celem is /etc/ssl/certs)"
else
	ok "elements: $_fxel from the fixtures, $celem from the trust store"
fi

printf '\n%d passed, %d failed, %d skipped\n' "$pass" "$fail" "$skip"
printf '%d DER elements compared against openssl asn1parse\n' "$elements"
[ "$fail" -eq 0 ]
