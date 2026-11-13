# derx

An ASN.1 DER reader and X.509 certificate printer in one C11 file, written to
be checked against `openssl`, not against my own reading of X.690.

```
derx parse FILE    the DER structure: offset, depth, header length, length,
                   constructed/primitive, tag, value
derx cert  FILE    X.509 certificate fields
```

`FILE` of `-` reads stdin. Input is DER. There is no base64 decoder here, so a
PEM file has to go through `openssl x509 -outform DER` first.

## Build

```
make          # derx
make test         # runs make overread first
make test-asan
make overread     # the sanitizer gate on slurp(), on its own
make clean
```

Pure C11, gcc, no libraries: not even zlib. `openssl` is called by the test
harness and never by `derx`.

## The oracle

`openssl` 3.5.7 decides whether `derx` read the bytes correctly. Nothing in
`t/run.sh` is an expected value I wrote down.

The main assertion is as strong as an assertion gets, because it is a diff:

```
derx parse FILE   ==   openssl asn1parse -i -in FILE -inform DER
```

byte for byte, on anything that is valid DER. That was the first design
decision and it shaped everything else: the column layout, the tag names,
the value formats are openssl's, down to the trailing blanks on a line with no
value, so there is no normalisation step in the middle that could be wrong in
a way that hides a disagreement.

Currently **13,034 DER elements** compare identically, of which 9,627 come
from the 150 distinct certificates in `/etc/ssl/certs`.

Those are fixed inputs. `t/fuzz.py` is the same diff against inputs nobody
chose: it mutates the corpus and runs both programs over every mutant. At the
seed and count `make test` uses, 600 mutants, around 371 of them are parsed by
both programs and compared, and the count that reached a comparison is
asserted, not just the count that differed. A run where every mutant was
refused before parsing has compared nothing and must not report a pass.

"Around" is the honest word and this file used to give an exact number.
Consecutive runs of an unchanged tree reported 372, 373 and 374: the mutant
stream is a pure function of the seed and of the corpus, and 16 of the corpus
files are certificates `openssl req` generated during that run, with a fresh
key each time. What is asserted is the floor of 250, which is why the
wandering does not matter; what was wrong was presenting the figure as fixed.

`derx cert` is judged by three different openssl subcommands. Five of its nine
fields are free: `openssl x509 -noout -serial -issuer -subject -startdate
-enddate` prints lines beginning `serial=`, `issuer=`, `subject=`,
`notBefore=` and `notAfter=`, so `derx cert` uses those exact spellings and
the comparison is again a plain diff. The other four, version, signature
algorithm, key algorithm, key size, have no one-line flag and come out of
`-text`. Extension values are checked one at a time against
`openssl x509 -ext NAME`.

Names are printed per `-nameopt RFC2253`, not openssl's default output.
Not because it is prettier: RFC 2253 is a published document whose escaping
rules can be implemented from the text, where matching openssl's default would
be imitating one program's habits.

### Ranked, least controlled first

1. `/etc/ssl/certs`. 150 real certificates issued by real CAs over
   twenty-five years, read-only. They carry encoder habits nothing generated
   locally reproduces: a T61String in Entrust's 1999 root, a GeneralizedTime in
   Certum's 2011 one, OIDs openssl itself cannot name and prints in dotted
   form, an authority key identifier carrying a full issuer name and serial.
2. Objects from openssl's own encoder. RSA at 1024, 2048 and 3072 bits
   against SHA-1, SHA-256 and SHA-512; EC on P-256, P-384 and P-521; Ed25519;
   a `notAfter` past 2049, which forces a GeneralizedTime and so puts two
   different time encodings in one certificate; a subject carrying all 24
   X.520 attribute types; names with an embedded comma, with leading and
   trailing spaces, and a multi-valued RDN; SAN, EKU and basic constraints.
   Then five shapes a certificate never has: a PKCS#10 request, a PKCS#1
   private key whose nine INTEGERs are the widest in the suite, a PKCS#8
   PrivateKeyInfo for the long hex-dump path, an EC private key, and EC
   parameters, which are a bare OID with no SEQUENCE around them.
3. Hand-built DER, byte by byte. The tag-name table for all 31 universal
   tags, the three other tag classes, the high-tag-number form, every INTEGER
   sign boundary, and a complete v1 certificate with an attribute type openssl
   cannot name and a 16-bit RSA modulus. This group exists because openssl's
   generator will not emit any of it, and every one of these is a live code
   path. The certificate template has knobs for the commonName value, the
   validity, the modulus, the extensions and the unique identifiers.
4. Malformed input, where both programs refuse. Truncation at every
   boundary, a child overrunning its parent, a length declaring two gigabytes,
   nesting 4000 deep, a tag number too wide to represent.
5. Valid BER that is not valid DER, where openssl accepts and `derx`
   refuses. Each of these asserts openssl's exit 0 as well, so "openssl is
   more permissive here" stays a measured fact, not a claim in this
   file. The list is in [What derx refuses that openssl
   accepts](#what-derx-refuses-that-openssl-accepts).
6. Two sweeps openssl cannot judge. Every prefix of a real certificate
   (508 inputs) and every single-byte corruption to `00` and to `FF` at every
   offset (1016 inputs), asserting only that the exit status stays at or below
   2, never a signal, never a sanitizer abort. openssl has an opinion about
   what bytes mean. It has none about whether we read outside them.

### `make test`

```
oracle: OpenSSL 3.5.7 9 Jun 2026 (Library: OpenSSL 3.5.7 9 Jun 2026)
under test: ./derx

ok    tag 0: the name openssl prints
...
ok    tag 30: the name openssl prints
ok    universal tag 1 may not be constructed
...
ok    universal tag 17 may not be primitive
ok    universal tag 0 is classified neither way
...
ok    universal tag 29 is classified neither way
ok    application class, primitive
ok    high tag number, universal 129
ok    INTEGER -512, kept zero byte
ok    INTEGER -65535, dropped zero byte
ok    OCTET STRING 0x7f is not printable
ok    OID 2.999, not 26.39
ok    OID arc wider than 64 bits
ok    OID table: 69 rows read out of derx.c
ok    OID table row 2.5.4.3
...
ok    OID table row 2.23.42.7.0
ok    cert: rsa2048-sha256
...
ok    system trust store: 150 certificates converted to DER
ok    /etc/ssl/certs: 9627 elements byte-identical to asn1parse
ok    cert fields: hand-built v1, unknown attribute OID, 16-bit key
ok    cert fields: T61String byte 0xC1 is Latin-1, not T.61
ok    cert fields: UTCTime 49 is 2049 and 50 is 1950
ok    cert fields: key usage with a nonzero unused bit
ok    cert fields: version 1 carrying an extension
ok    cert fields: issuerUniqueID and subjectUniqueID are skipped
ok    cert fields: 150 certificates, 9 fields and every extension name
ok    cert extension values: 483 compared, 0 disagreed with openssl
      basicConstraints         trust store: 150 agree, 0 declined (floor 120, 0)  fixtures: 16
      keyUsage                 trust store: 147 agree, 0 declined (floor 120, 0)  fixtures: 7
      extendedKeyUsage         trust store:   0 agree, 0 declined (floor 0, 0)  fixtures: 1
      subjectKeyIdentifier     trust store: 149 agree, 0 declined (floor 120, 0)  fixtures: 16
      authorityKeyIdentifier   trust store:  29 agree, 5 declined (floor 15, 15)  fixtures: 16
      subjectAltName           trust store:   2 agree, 1 declined (floor 1, 5)  fixtures: 1
ok    per-extension counts: six extensions, each above its own floor
ok    truncated: content short by exactly one byte
ok    child short by one byte reads into its sibling
ok    nesting 128 deep, accepted by both
ok    nesting 129 deep, refused by both
ok    indefinite length (BER only)
ok    constructed OCTET STRING (BER segmenting)
ok    truncation sweep: every prefix of a certificate (508 inputs)
ok    single-byte corruption sweep: 00 and FF at every offset (1016 inputs)
ok    differential fuzzer, 600 mutants
      | fuzz: 371 compared and agreed, 0 mismatched, 5 differed only in an
      | OID name, 83 refused by derx alone, 141 refused by both, 0 accepted
      | by derx alone, 0 crashed, 0 undiagnosed
ok    fuzzer: mutant i is a pure function of (seed, i)
ok    stdin arriving one byte at a time reads the same
ok    harness: agree fails on a differing OBJECT value
ok    harness: agree fails when both programs refuse the input
ok    harness: reject fails when derx accepts the input
ok    harness: reject fails when openssl accepts what is claimed as shared
ok    harness: certreject fails when openssl accepts the certificate
ok    harness: certstricter fails when openssl refuses it too
ok    harness: certexts fails when no extension was compared
ok    harness: sweep fails on an empty directory
ok    harness: reject fails on a refusal with no diagnostic
ok    harness: reject fails on exit 2 where it wants exit 1
ok    harness: sweep fails on a status above 2
ok    assertions: 336 above this line, the number this file expects
ok    elements: 3407 from the fixtures, 9627 from the trust store

338 passed, 0 failed, 0 skipped
13034 DER elements compared against openssl asn1parse
```

The last thirteen lines are the suite checking itself. Eleven of them run an
assertion against an input, or against a stub program, chosen to make that
assertion fail, and require it to fail: a check that has never been seen to
report a failure may be checking nothing, and ten of twenty mutations to
`t/run.sh` used to leave it green. The twelfth is the number of assertions
the file ran, compared against a literal, because a group that stops running
leaves nothing behind but a smaller number. The thirteenth splits the element
total into the part the fixtures produce and the part that comes from
whatever is in `/etc/ssl/certs`, so the share that moves with the machine is
visible and the share that does not can have a floor. Both are in
[Breaking the harness on purpose](#breaking-the-harness-on-purpose).

`make test` depends on `make overread`, which is the sanitizer gate on the two
places in the program where a buffer could be larger than its contents. It
prints two lines of its own above the suite:

```
ok    overread: ASan sees the planted read one byte past the file
ok    overread: ASan sees the planted read past the attribute array
```

Each builds a binary with a deliberate read compiled in and fails unless ASan
reports it and the process exits 86. `derx` itself exits 0, 1 or 2 and nothing
else, so 86 cannot be read as a refusal, a usage error or a crash.
`-DDERX_OVERREAD` reads `b[n]`, one byte past the end of the input buffer, and
wants a `heap-buffer-overflow`. `-DDERX_OVERREAD_ATV` reads `a[na]` in
`print_name()`, one past the attributes a certificate's name actually carried,
and wants a `dynamic-stack-buffer-overflow`, which is a different class and is
asked for by name rather than as "some error happened". Everything either one
builds lives in a fresh `mktemp -d` and is removed, so nothing is left in the
tree.

The gate asks ASan alone on purpose. With `-fsanitize=undefined` as well,
UBSan reaches both plants first and halts on its own message, so the target
would be asserting a string from the wrong instrument. That second message is
worth knowing though: sizing the array to the count is also what gives UBSan a
bound to check, so it reports `index 1 out of bounds for type Atv [*]` where
the fixed array gave it nothing to say.

The gate exists because nothing else in the suite can see the property. With
the `realloc` down to the file's exact size removed from `slurp()`, the whole
suite reports `338 passed, 0 failed` and `make test-asan` reports the same,
while `make overread` fails with `exit 0, no heap-buffer-overflow reported`.
Both numbers were measured that way, not assumed.

`make test-asan` runs the identical suite under
`-fsanitize=address,undefined`, including both sweeps, in about seventy
seconds against a plain run's forty-five. It is not a dependency of
`make test`, so it is a target somebody has to remember, and the figure above
is from running it at this commit rather than from the last time it was
quoted.
`ASAN_OPTIONS=exitcode=86` is load-bearing and not decoration. A sanitizer
abort exits 1 by default, the suite asserts exit 1 for "cleanly refused this
input", and without the override a heap overflow would have scored as a
correct diagnostic. That collision is a defect `inflate` found the hard way in
this same set of repositories, and the number is copied from there.

If `openssl` is not on `PATH`, `t/run.sh` exits 2 instead of reporting skips.
Every expected value comes from it, so without it the suite would be comparing
`derx` to `derx`, and that is no pass at all.

## What works

- Definite-length DER, all four tag classes, the high-tag-number form, nesting
  to openssl's own limit of 128.
- The form rules: 22 universal tags that may only be primitive and 3 that may
  only be constructed, each refused in the wrong form, with openssl's
  acceptance of all 25 asserted beside the refusal. The six tags openssl has
  no name for are classified neither way, and both forms of those are
  compared rather than refused.
- Values printed for the tags openssl prints values for: BOOLEAN, INTEGER and
  ENUMERATED (sign and magnitude, including the negation of a negative), OBJECT
  IDENTIFIER (arbitrary-width arcs, named from a 69-entry table or dotted),
  OCTET STRING (as text when it looks like text, as hex otherwise), and
  UTF8String, NumericString, PrintableString, T61String, IA5String, UTCTime,
  GeneralizedTime and VisibleString as raw bytes.
- From a certificate: version, serial, signature algorithm, issuer and subject
  as RFC 2253 strings, validity in openssl's date layout, public key algorithm
  and size for RSA and EC.
- Six extensions decoded: basic constraints, key usage, extended key usage,
  subject key identifier, authority key identifier (keyid-only form), subject
  alternative name (DNS, IP, email, URI). Every other extension's name and
  critical flag is still printed and still checked. Only its value is not
  decoded.
- Every malformed input is refused with a diagnostic on stderr and exit 1.
  Exit 2 is reserved for a usage error. Nothing reads or writes out of bounds,
  under ASan and UBSan, across 1524 mutated inputs, and `make overread` is the
  gate that keeps that claim worth making.

  The whole file was swept for buffers declared larger than their data, the
  shape that turns the sanitizer off, rather than revisiting the one function
  that was fixed last time. There is exactly one heap allocation in `derx.c`,
  `slurp()`'s input buffer, and it is the one already trimmed to the file's
  exact size. There is no writable object with static storage at all: `.data`
  and `.bss` are both zero bytes, and every static object is a `const` table.
  So the variant that no sizing fix reaches, a fixed array in static storage
  holding untrusted input, is absent here by construction rather than by care.
  Ten stack arrays remain, each bounded by a guard that calls `die()`, and a
  planted read one past the end of one of them is reported as a
  `stack-buffer-overflow` with a line number, measured rather than assumed.
  The eleventh was `print_name()`'s attribute array, the one place no
  allocation size could reach, and it is sized to the name that was decoded
  now rather than to a fixed 256, with a probe of its own in
  `make overread`.

## What does not work

This is the half of the document that matters.

### ASN.1 that derx does not handle

- No indefinite lengths, which means no BER. This is deliberate. It is
  the first thing DER removes, but it also means `derx` cannot read a CMS or
  PKCS#7 blob produced by a streaming encoder, a real and common
  shape. openssl reads those and prints `l=inf`.
- No constructed strings. BER lets an OCTET STRING travel as a sequence of
  segments. DER does not, so `derx` refuses it. Same reasoning, same
  consequence: a legitimate BER file is unreadable.
- No REAL, no EXTERNAL, no EMBEDDED PDV, no CHARACTER STRING, no
  RELATIVE-OID, no TIME. Their headers are decoded and their tag names
  printed, since openssl does the same, but no content is interpreted. openssl
  prints no value for any of them either, so `derx parse` agrees, but the
  agreement is two programs both declining, not two programs both decoding.
- Tags 11, 13, 14, 15 and 29 are not classified as primitive-only or
  constructed-only, where the other 26 universal tags are. openssl has no name
  for them, so the oracle has no opinion, and inventing one would be writing a
  test against my own expectation.
- BMPString and UniversalString are decoded only inside a distinguished
  name. In `derx parse` they print no value, as openssl does;
  there is no `--show-strings` mode that would decode them, because there would
  be nothing to check it against.
- An OID arc wider than about 2^425, or an OID beyond roughly 127 arcs, is
  refused by name, not printed. openssl reaches for a BIGNUM and has
  no such limit. Marked `shortcut:` in the source with the upgrade path.
- The first arc of an OID must fit in 64 bits. Unpacking 40*X + Y needs
  arithmetic; the later arcs go through arbitrary-precision decimal and agree
  with openssl at 2^71.
- A DER object larger than RAM cannot be parsed at all. The whole file is
  read into one buffer. Marked `shortcut:`.
- A distinguished name with more than 256 attributes is refused by name.
  Marked `shortcut:`. The certificates on this machine use at most five.

### X.509 that derx does not decode

- No cryptography of any kind. No signature is verified, no hash is
  computed, no key is used. `derx cert` will happily print the fields of a
  certificate whose signature is four bytes of `DE AD BE EF`, and the test
  suite relies on that. **`derx` tells you what a certificate says, never
  whether it is true.** Do not make a trust decision with it.
- No chain building, no validation, no expiry check, no name matching, no
  revocation. It prints `notAfter`. It has no opinion about today's date.
- Key sizes only for RSA and EC, and for EC only the three curves the
  corpus and the fixtures contain (P-256, P-384, P-521). Any other algorithm
  prints `keybits=-`. For Ed25519 that is not a gap but the honest answer:
  openssl prints `ED25519 Public-Key:` with no bit count, so there is no number
  to agree with, and the suite asserts the absence.
- Only the keyid-only form of the authority key identifier. Five of the 150
  certificates here carry one with an issuer name and serial as well, which
  openssl prints on three labelled lines. The one-line-per-extension format has
  nowhere to put them, so the value prints as `?`. Those five are five of the
  six declines the suite counts, and the suite holds
  `authorityKeyIdentifier`'s declines under a tenth of the store for that
  reason rather than letting them disappear into one aggregate.
- Subject alternative name covers four of nine GeneralName kinds,
  dNSName, iPAddress, rfc822Name, uniformResourceIdentifier. A directoryName,
  otherName, x400Address, ediPartyName or registeredID anywhere in the list
  makes the whole value print as `?`, deliberately: a partial list of the names
  a certificate is valid for is worse than no list. One corpus certificate has
  a DirName and is the sixth decline. The other four decoded extensions have no
  multi-line form at all, so a `?` from any of them is `derx` failing at
  something it claims to do, and the suite holds each of their decline counts
  at exactly zero.

  These six are declines, not refusals. `derx` still parses the file, still
  prints the extension's name and critical flag, and still agrees with openssl
  about both; it declines only the value. The suite counts them apart from
  disagreements for that reason, and a disagreement fails the run where a
  decline is measured against its own ceiling.
- The other extensions are names only. CRL distribution points,
  certificate policies, authority information access, name constraints, policy
  constraints, inhibit anyPolicy, private key usage period, Netscape cert type:
  the extension's name and critical flag are printed and compared, and the
  value prints as `?`.
- No CRLs, no PKCS#7, no PKCS#12, no OCSP, no CSR field printing. `derx
  cert` refuses a certificate request, and the suite asserts that it does.
- A signature algorithm's parameters are not examined. An RSASSA-PSS
  certificate prints `sigalg=rsassaPss` and nothing about the hash or salt
  length inside the parameters, where openssl's `-text` spells all of it out.
  There is no PSS certificate in the corpus, so this is untested as well as
  unimplemented.
- The OID table has 69 entries and is data I typed. An OID openssl names
  and `derx` does not makes `derx parse` print digits where asn1parse prints a
  name, which fails the corpus diff. That is the intended failure mode, loud,
  not silent, but it does mean a certificate carrying an OID outside the
  table breaks the suite instead of degrading gracefully.

  Each of the 69 rows is now driven through both programs: `openssl asn1parse
  -genstr OID:<dotted>` encodes the row's own dotted value and asn1parse
  names it back, so a misspelled name fails on that row and so does a wrong
  dotted value, since the name openssl prints belongs to the OID that was
  actually encoded. Until that group existed the table was checked only where
  some input happened to carry the OID, which left 14 rows typed and never
  read back: `rsassaPss`, `ecdsa-with-SHA1`, `ED448`, seven extension names
  from Subject Directory Attributes to Inhibit Any Policy, and four of the
  seven extended key usage purposes. All 69 agree, so nothing was wrong in
  the table; what was wrong was the claim that it had been checked.

  The fuzzer measures the gap, because mutating the content of an OID is how
  you reach the arcs no real certificate in the corpus carries. Over 10,000
  mutants at three seeds, 30 produced a file both programs parsed where the
  only difference was openssl having a name and `derx` printing digits:
  `supportedApplicationContext`, `x121Address`, `dmdName`, `X509v3 CRL
  Number`, `secp192k1` and so on. Those are wrong answers, and the fuzzer
  counts them on their own line rather than inside the mismatch count, which
  is a judgement call and the reason it is written down here: they are one
  known missing table, not thirty separate bugs, and growing that table from
  openssl's `objects.txt` is an item in `PLAN.md`. The test for the category
  is narrow on purpose. Every differing line must be an OBJECT line identical
  in offset, depth, header length and length, with `derx`'s value purely
  numeric and openssl's not. A *different* name, or different digits, stays a
  mismatch and fails the run.

### Where derx and openssl are not comparable

- Error messages and partial output. When both refuse a file, only the exit
  status is compared. openssl's diagnostics and ours differ entirely, and both
  programs print the elements they managed to read before stopping, so the
  stdout of a failed parse is not compared either.
- An input openssl refuses to read as a certificate has no cert oracle.
  A VisibleString or an INTEGER as an attribute value makes openssl decline to
  build a name at all, so for those inputs there is nothing to compare `derx
  cert` against. `derx` refuses them too, and the suite asserts the shared
  refusal, but that is agreement about unreadability, not about meaning.
- `derx parse` of a key usage BIT STRING's bits. openssl's asn1parse prints
  no value for a BIT STRING, so the bit-level decoding is only checked through
  `derx cert` and `openssl x509 -ext keyUsage`.

### Where openssl and GnuTLS disagree

openssl is the only oracle here, and two places on this machine show what
that costs. Both were found through `certlint`, a sibling repository that
runs OpenSSL and GnuTLS against each other, and both were re-measured here
rather than quoted.

A version 1 certificate carrying an extension. RFC 5280 4.1.2.1 requires
version 3 for extensions. `openssl x509 -text` reads the file and prints
`Version: 1 (0x0)` with the key usage underneath it; `certtool
--certificate-info` refuses the whole file with `import error: Error in the
certificate`; `certlint` refuses it at its parser. `derx` reads it and prints
`version=1` with the extension, so it is doing what its oracle does. There is
a hand-built fixture for it and three assertions on it, all of them against
openssl, which is the honest limit of what this suite can say.

The bit length of a P-521 key. openssl prints `Public-Key: (521 bit)`.
certtool prints `Algorithm Security Level: Future (528 bits)`, which is 66
bytes rounded up to a byte boundary and is also a differently named quantity.
`derx` prints `keybits=521` because openssl's line is what it is compared
against.

Neither is settled here. A reader with one oracle cannot say which of two
oracles is right, and picking the one that makes `derx` look correct would be
choosing the answer first. What `derx` can say is which program it agrees
with, and it says so.

### What derx refuses that openssl accepts

Thirty-nine cases in `derx parse` and six more in `derx cert`. DER is a
subset of BER and openssl reads BER, so each of these is a second encoding of
a value that DER already has one encoding for. Each one is asserted in the
suite *including openssl's exit 0*, so the divergence is measured, not
described. Twenty-five of the thirty-nine are the wrong form of one tag, a
row each in the table below:

| input | openssl | derx |
|---|---|---|
| indefinite length | `l=inf` | refused |
| long-form length for a length under 128 | read | refused |
| long-form length with leading zero octets | read | refused |
| INTEGER with a redundant leading `00` or `FF` | `BAD INTEGER` | refused |
| INTEGER of zero length | `BAD INTEGER:[]` | refused |
| BOOLEAN `TRUE` encoded as `01` | `:1` | refused |
| BOOLEAN of two bytes | `BAD BOOLEAN` | refused |
| OID of zero length | `BAD OBJECT:[]` | refused |
| OID arc padded with a zero septet | `BAD OBJECT` | refused |
| OID content ending mid-arc | `BAD OBJECT` | refused |
| constructed OCTET STRING, and the other 21 tags that may only be primitive | read and descended | refused |
| EXTERNAL, SEQUENCE or SET in the primitive form | read | refused |
| high tag number padded with a zero septet | read | refused |
| high tag number form used for a tag below 31 | read | refused |
| SEQUENCE or BIT STRING as an attribute value | dumped as hex | refused |
| `critical FALSE` encoded explicitly | read as not critical | refused |
| a modulus with two leading zero bytes | padding ignored | refused |
| a NULL after the certificate | first object taken | refused |
| a name with more than 256 attributes | read | refused by name |

The last group is the one worth defending. `derx` is narrower than openssl
about distinguished names on purpose: it never prints a name openssl would have
refused to read. For a tool whose output somebody might compare against
something, that is the safe direction.

## Where the tests are still weak

- The fuzzer is not coverage-guided. `t/fuzz.py` mutates and compares, and
  it has no idea which branches of `derx.c` it reached. Five of its eight
  mutators are blind byte edits whose results are mostly refused by both
  programs before anything is printed; the other three keep the framing
  intact, which is why most of its comparisons happen at all. Measured at
  seed 1 over 1000 mutants: of the structure-aware mutators, swapping two
  siblings reached a comparison 168 times out of 168, a content byte 201 of 240
  and a retag 114 out of 218, against 0 out of 61 for truncation and 1 out of
  58 for splicing. So the honest description is a mutation fuzzer with a
  differential oracle, not a coverage-guided one: nothing steers it toward an
  unvisited branch, and a path that needs two coordinated edits to reach is
  as unlikely on the thousandth mutant as on the first.
- The fuzzer has found one class of wrong answer and no others. Over 10,000
  mutants at three seeds there were 0 mismatches and 30 OID-name gaps, all of
  the one kind described above. That is a real result, not a vacuous one, and
  the numbers that make it not vacuous are the 6,390 mutants that both
  programs parsed and compared. But "no crashes, no disagreements" over this
  corpus is a weaker statement than it sounds: the corpus is 150 CA
  certificates and 70 generated files, all of which `derx` already parses, so
  the mutants are all a short edit distance from something that works.
- What the fuzzer is checked against is planted defects, and all four
  planted were already covered. Four defects were put into `derx.c` one at a
  time and the fuzzer caught all four at the seed and count `make test` uses:
  an off-by-one in the two's-complement negation (2 mismatches), a misspelled
  tag-21 name (4 mismatches), the non-minimal INTEGER rule deleted (3
  mismatches), and the content-length bounds check deleted (31 crashes and 31
  files accepted that openssl refused). The honest caveat is that the
  existing hand-built assertions also caught all four, so none of them
  demonstrates reach the suite did not already have. The two things the
  fuzzer found that nothing else did are the OID-name gap and the sanitizer
  blindness in item 7 below.
- The corpus the fuzzer mutates is this machine's `/etc/ssl/certs`. The
  mutant stream is a pure function of the seed *and the corpus*, so the same
  seed on a machine with a different trust store is a different run. The
  reproduction that always works is the saved file, which the fuzzer writes
  for every failure.
- The deep-nesting limit is tested at 128, 129 and 4000, not at the stack.
  4000 levels is refused by the depth check, which means the recursion itself
  has never been pushed to where it would actually break. It cannot be, while
  the check is there, and that is the point, but it does mean the claim is
  "the check works", not "the recursion is safe without it".
- One mutation survives and should not be chased. Deleting the leading-zero
  scan from `int_bits()` leaves every assertion in the suite green, and it is provably
  equivalent on anything `derx` will read. A minimal INTEGER has at most one
  leading zero byte, and only when the next byte has its high bit set. In that
  case the version with the scan computes `(n-2)*8 + 8` and the version without
  computes `(n-1)*8 + 0`, because the bit-counting loop contributes nothing for
  a zero top byte. The two differ only on a second pad byte, which X.690 8.3.2
  forbids and which `int_check()` refuses before `int_bits()` ever runs.
- The buffer that was larger than its contents is fixed, and this entry stays
  because of what it took to see. `print_name()` held the flattened
  attributes of a distinguished name in `Atv a[256]` where the certificates
  here use at most five, so a read at `a[na]`, one past the attributes
  actually decoded, never left the array: planted and built with
  `-fsanitize=address,undefined` it produced no diagnostic of any kind and
  the program exited 0. There was no redzone to cross. It was never a live
  defect, since every write is guarded and the printing loop runs from
  `na - 1` down, and that is exactly why nothing could find it.

  `print_name()` walks the name twice now, once to count the attributes and
  once to fill an array sized to that count. The same planted read is a
  `dynamic-stack-buffer-overflow` with a line number, and `make overread`
  plants it on every `make test`. No build flag and no second configuration,
  which is where this differs from `jsonc`'s arena: there was no speed to
  protect, so there is one path rather than two.

  Two things that did not move, both measured. With the array put back to
  `Atv a[256]`, `make test` and `make test-asan` both still report `338
  passed, 0 failed`, and `make overread` is the only thing that fails. And the
  bound itself had never been reached by any input. `MAXATV` is what keeps the
  length of that array off the certificate, and with a counting pass it is the
  certificate that proposes the length, so there is a fixture now with 257
  attributes in its subject: openssl generates it and reads it, `derx cert`
  refuses it by name, and deleting the bound turns that one assertion red
  where nothing would have noticed before.

- No oracle for an unknown attribute type with a non-string value. openssl
  dumps it as hex and `derx` refuses it; a *known* attribute type with a string
  value under an unnamed OID is covered by the hand-built fixture, but the
  cross product is not.
- Six extensions are decoded and one of them has no trust-store coverage at
  all. That sentence was invisible until the group was counted per extension
  instead of in total. `extendedKeyUsage` appears in 0 of the 150 certificates
  in `/etc/ssl/certs`, because a CA root does not carry one, and its whole
  coverage anywhere in this suite is the single generated leaf fixture
  `ext-ku`. Deleting that one fixture takes it to zero everywhere, and the old
  aggregate assertion stayed green when that was tried: 477 agreements, 6
  declines, both inside their thresholds.

  The counts are now per extension, printed, and each has its own floor.
  `basicConstraints`, `keyUsage` and `subjectKeyIdentifier` supply 446 of the
  477 between them, so the total tracked those three and absorbed everything
  else; an extension with two cases and one with a hundred and fifty both read
  as "agrees".

  The floors are still floors on the trust-store side and not the measured
  numbers, deliberately. The group above accepts a store of as few as 100
  certificates on the stated grounds that a thinned store should still run, and
  an exact 150 would call a thinned store a broken `derx`. They are fractions
  of the store's size: four fifths of it for the three near-universal
  extensions, a tenth for `authorityKeyIdentifier`, 1 for `subjectAltName`,
  which is the honest minimum below which it is not exercised at all. The
  fixture counts are exact equalities, because those inputs are built by
  `t/run.sh` and nothing outside the repository can move them.

## On being wrong

The project's thesis is that the oracle beats my reading of the standard, and
it collected receipts:

- openssl's tag names are not X.680's. Tag 20 is TeletexString in the
  standard and `T61STRING` to openssl. Tag 26 is VisibleString and prints as
  `VISIBLESTRING`, not the `ISO64STRING` an older openssl used. Both were wrong
  in the first draft of the table and the suite said so on the first run.
- openssl's string conversion is not the types' own charsets. Every
  one-byte-per-character type goes through `MBSTRING_ASC`, which treats the
  byte as a code point, so a T61String byte `0xC1` becomes U+00C1, Latin-1
  capital A-acute, and not T.61's combining acute accent, the character the
  type's charset says it is. A PrintableString byte `0xE9` gets the same
  treatment, despite `0xE9` not being in PrintableString's charset at all.
- The 40*X+Y unpacking caps X at 2. Without the cap, `2.999` decodes as
  `26.39`. Checked at 0.0, 0.39, 1.0, 2.0 and 2.999.
- openssl keeps some leading zeros in a negative magnitude and drops
  others. -512 is `FE 00` and prints as `-0200`; `FF 00 01` negates to
  `00 FF FF` and prints as `-FFFF`. One rule, two appearances, and I had
  guessed a different rule.
- A UTCTime with no seconds is refused by openssl, not defaulted to zero.
  That test was written as a derx-is-stricter case and reclassified.

## The harness is usually the bug

Most of the defects recorded across these repositories were in a test rig, not
in the code. Ten of this one's were:

1. The off-by-one the suite could not see. Changing the content bounds
   check from `end - i < len` to `end - i + 1 < len` left all 121 assertions
   green. Every truncation fixture was short by three bytes or more, so a check
   that is off by one still caught them. Short by exactly one is the overread
   that actually happens, and the nested version of it, where the byte past
   the child's end is its sibling's tag, inside the file, is invisible
   to ASan and visible only because openssl refuses the file.
2. The two-digit year pivot had no boundary case. `>= 50` versus `>= 49`
   changed nothing, because openssl's own generator emits a GeneralizedTime for
   anything past 2049 and so cannot produce a certificate at the boundary.
3. The key usage unused-bit count was dead arithmetic. Deleting it changed
   nothing, because every key usage in the corpus has its padding bits already
   zero.
4. The unique-identifier skip was dead code. Deleting it changed nothing,
   because RFC 5280 tells CAs not to generate those fields and none of the 150
   certificates has one.
5. `rd_end()`'s trailing-bytes check was dead. Deleting it changed nothing,
   because no fixture had trailing bytes anywhere. Six do now.
6. Two fixtures were wrong while derx was right. The "child runs past its
   parent" case was `30 06 05 00 05 00 05 00`, a valid SEQUENCE of three
   NULLs. And the hand-built certificate's length arithmetic assumed a
   four-byte TBSCertificate header where it is three, so fifteen fixtures were
   one byte short and `derx` correctly rejected every one of them.
   `handcert()` now verifies that `derx` can parse each template it builds.

7. `make test-asan` could not see a read past the end of the file. `slurp()`
   allocated 64 KiB and never gave the slack back, so for a 1 KiB certificate
   every byte a parser bug might read past the last content octet was inside
   a live allocation and no sanitizer had anything to say about it. The
   fuzzer found this by catching the planted missing bounds check as "derx
   accepted 33 files openssl refused" while ASan reported zero errors on all
   600 mutants. `slurp()` now reallocs down to the exact file size, and the
   same plant produces 31 ASan aborts. This is the general shape of the trap:
   a sanitizer gate that has never been watched to fail is a gate whose reach
   is a guess.
8. The fuzzer's own determinism assertion was checking its own echo. It
   ran the fuzzer twice at one seed and once at another and compared the
   logs, and it passed with `--seed` deliberately ignored, because the logs
   still differ on the line that prints the seed back. It now compares
   SHA-256 digests of the mutants themselves, in three claims: 40 mutants are
   produced, `--start 30 --count 10` is byte-identical to the last ten of
   them, which is the promise that a saved failure replays by index, and
   seeds 2 and 3 do not produce the same 40. Both ways of breaking the seed
   wiring are now caught.
9. The fix to item 7 had no gate, so it could be undone silently. `slurp()`
   was corrected on 18 October and the correction was written up here and in
   `PLAN.md`, and nothing has checked it since. Removing the `realloc` leaves
   the whole suite reporting `338 passed, 0 failed`, under the sanitizers as
   well as without them. `make overread` is the only thing that notices, and
   it is a dependency of `make test` rather than a target somebody has to
   remember, because two repositories in this collection had the target and
   never ran it.
10. An extension's oracle could stop running without anything saying so.
   The trust-store extension group reported one total, and deleting
   `keyUsage` from the harness's list of extensions to ask openssl about left
   that total at `330 agree, 6 declined`, which cleared the floor of two
   agreements per certificate and passed. Four key usage fixtures did fail,
   through the vacuity guard in `certexts`, so the suite went red, but nothing
   in it said that an oracle had stopped running: the group that was supposed
   to measure keyUsage printed a pass. The first version of the per-extension
   replacement had the same hole, because it iterates that list and a deleted
   name takes its row and its floor with it. The list's length is asserted
   now.
11. A table can be enumerated in the source and never driven. The 69 rows of
   `oidtab[]` were described in `derx.c` as verified by diff, and the
   verification was conditional on some input carrying the OID: 14 rows are
   carried by nothing in `/etc/ssl/certs`, nothing openssl's generator emits
   and no fixture, so they were typed and read back by nothing. Measured by
   collecting every OBJECT name the oracle prints over every input the suite
   builds and subtracting it from the table, not by reading the code.
   Misspelling `Time Stamping` in one of those rows left the suite at `288
   passed, 1 failed` once the new group existed and would have passed before
   it. Nothing was wrong in the table; the claim about it was wrong.
12. The main oracle could be disconnected without a word being said.
   Replacing the `cmp` in `agree()` with `true`, so that the diff between
   `derx parse` and `asn1parse` never runs, left `289 passed, 0 failed`. One
   word turned the strongest assertion in the project into 163 passes over
   comparisons that did not happen, and nothing else in the file compares
   those two byte streams. It is caught now by a probe on an OID openssl
   names and `derx` does not, the one disagreement this suite can produce on
   demand.

Fifty-one distinct mutations were applied, twenty-five to the DER reader,
twenty-six to the certificate reader. Six survived a suite that was green at
the time: the off-by-one above, the year pivot, the key usage padding bits, the
unique-identifier skip, `rd_end()`, and `int_check()` not being shared between
the two subcommands. Five are now killed by a named assertion. The sixth is the
provably equivalent one above and will stay alive.

Five more were applied against the per-extension counts and the overread gate,
three to `derx.c` and two to `t/run.sh`, and all five are killed. Two of the
five, the third and the fifth, were passed by the whole suite as it stood, and
a third had the extension group reporting a pass while the suite went red
somewhere else. The old numbers are worth writing down beside them:

| mutation | old suite | now |
|---|---|---|
| `keyUsage` declines when its BIT STRING carries two value octets | 475 agree, 8 declined, group passed; killed only by a fixture | `keyUsage: 2 declined, ceiling 0`, and its fixture count 5 against 6 |
| `keyUsage` removed from the harness's extension list | `330 agree, 6 declined`, group passed | the list's length is 5, not 6 |
| the `ext-ku` fixture removed, which is the only `extendedKeyUsage` input anywhere | 477 agree, 6 declined, nothing failed | `extendedKeyUsage: 0 fixture agreements, expected exactly 1` |
| `subjectKeyIdentifier` stops being decoded | 16 fixtures failed | also the floor, the ceiling and the fixture count |
| the `realloc` down to the exact file size removed from `slurp()` | `338 passed, 0 failed`, with the sanitizers on | `make overread` fails, `exit 0, no heap-buffer-overflow reported` |

The fourth row found a defect in the replacement rather than in `derx`. Once
the thresholds moved out of the aggregate assertion it was left printing
`ok cert extension values: 328 agree, 155 declined`, a pass announcing a
number that should have failed, which is the shape of defect this collection
keeps finding: a line that says a check passed with no branch that could make
it say anything else. It reports what it actually checks now, that nothing
disagreed with openssl, and the counts sit next to the floors that judge them.

The two mutations to `t/run.sh` are not the planned harness sweep, which is
still queued in `PLAN.md` and will go over the whole file. They are there
because a per-extension count can only be broken from the harness: an
extension deleted from the list of names to ask openssl about takes its own
floor away with it, and that is not a defect `derx.c` can express.

No equivalent mutants in this group, and that is a thinner result than five
out of five looks. These five were written to exercise the assertions that
were just added, so all five dying says those assertions are wired up. It says
nothing about reach the suite does not have.

Four more were applied against the per-row OID table group, two to `derx.c`
and two to `t/run.sh`, and all four are killed:

| mutation | without the group | with it |
|---|---|---|
| `Time Stamping` misspelled, a row no input carries | nothing fails | `FAIL OID table row 1.3.6.1.5.5.7.3.8`, 288 passed, 1 failed |
| `ED448`'s dotted value changed to 1.3.101.114 | nothing fails | openssl prints the dotted form, derx prints `ED448`, 288 passed, 1 failed |
| the `sed` that reads the rows out of `derx.c` matches nothing | the group's 69 assertions disappear and the suite reports 219 passed | `0 dotted values parsed out of 69 rows in the block, floor 69` |
| the `awk` range that finds the table matches nothing | both counts are 0 and agree with each other | the floor of 69 fails |

The first two are the whole point of the group and the second two are why it
has a count: a group that reads its inputs out of a file can stop reading
them, and 69 assertions quietly becoming none is a pass with a smaller
number. The third mutation is what put the assertion count in the suite,
described below, since 219 against 289 was visible only to somebody who
remembered the number.

The one survivor of the earlier sweeps was re-measured rather than quoted:
deleting the leading-zero scan from `int_bits()` still leaves every
assertion in the suite green. No count is given, because that one moves with
every commit and the claim does not.

Three were applied against the attribute array, all killed, and the first
two are a pair worth reading together. Putting the array back to `Atv a[256]`
leaves `make test` and `make test-asan` both at `338 passed, 0 failed` with
`make overread` the only thing that fails, which is the same shape as the
`slurp()` row above: the gate is the only witness. Deleting the `MAXATV`
bound, which is what keeps the array's length off the certificate now that it
is sized by a counting pass, fails the new 257-attribute assertion and
nothing else, and would have failed nothing at all a commit ago. And
compiling the planted read with `-fsanitize=address,undefined` against the
fixed array produced no diagnostic from either sanitizer, measured with the
same probe the gate uses rather than with a separate experiment.

Three more were applied against the form rules, all killed and each at the
resolution it should have. Dropping one term from `prim_only` fails exactly
one assertion, the one for that tag. Deleting the constructed-form refusal
altogether fails 23: the 22 tags plus the constructed OCTET STRING case that
was already in section 8. Deleting the primitive-form refusal fails exactly
3. The per-bit measurement was done outside the suite, by compiling 25
copies of `derx` with one term missing from the mask in each, because 25
suite runs at 45 seconds is a worse way to learn the same thing.
13. The same shape again, in a bitmask rather than a table. 25 of the 31
   universal tags are classified in `derx.c` as primitive-only or
   constructed-only, and the suite drove one of those 25, the constructed
   OCTET STRING. Deleting `(1u << 2)` from `prim_only`, which lets a
   constructed INTEGER through, left every assertion green. 25 copies of
   `derx` were compiled, one term removed from the mask in each, and
   dropping bit N makes derx accept the wrong form of tag N and nothing
   else, so the 25 assertions now in the suite stand one to one against
   them. Found by asking the same question the OID table had just answered,
   rather than by a new idea.

### Breaking the harness on purpose

`PLAN.md` had an item for mutating this file instead of `derx.c`, on the
grounds that most of the defects above were in it. 20 mutations were applied,
one at a time, each run against an unmodified `derx`. Ten of the twenty left
the suite reporting `289 passed, 0 failed`.

Twelve are killed now. Eleven assertions run the harness against an input, or
against a stub program, chosen to make it fail, and require it to fail;
`guard` runs one assertion inside a command substitution, where its counters
cannot reach the real ones, and reads its first word. Two more assertions
count what the file did.

The right-hand column is the only assertion that failed in each of those
runs, which is how "ten of the twenty were invisible" is known: remove that
one assertion and the run has nothing to report. For the first row that was
measured rather than reasoned, by putting the mutation into the file as it
stood before this work: `289 passed, 0 failed`, with the diff that the whole
project rests on disconnected.

| mutation to t/run.sh | the only assertion that fails |
|---|---|
| the `cmp` in `agree()` replaced by `true` | the probe on secp192k1, an OID openssl names and derx prints in dotted form |
| `agree()`'s three status and line-count checks deleted together | the probe on the empty file, where both programs print nothing |
| `agree()` stops adding to the element count | `0 elements outside the trust store, floor 1000` |
| `reject()`'s check on openssl's exit status deleted | the probe asserting a BER file as a shared refusal, which is the whole difference between `reject` and `stricter` |
| `reject()`'s diagnostic check deleted | the probe against a stub that exits 1 in silence |
| `reject()` accepts any nonzero status, not exactly 1 | the probe against a stub that exits 2 |
| `sweep()`'s threshold raised from 2 to 200 | the probe against a stub that exits 86, which is what a sanitizer abort exits |
| `sweep()`'s empty-directory check deleted | the probe over an empty directory |
| `certexts()`'s no-extension-compared check deleted | the probe over the hand-built v1, which carries no extension |
| section 8 deleted, the fourteen BER cases openssl accepts | `317 assertions above this line, expected 331`, measured when the literal was 331 |
| the oracle call in `agree()` replaced by `true` | not one assertion but 163, from the branch that refuses to compare against an oracle that printed nothing |
| `certfields()`'s nine-field-lines check deleted | not one but 39, from the field diff itself |

The last two were already visible, and the second of them is worth naming
for what it says about that check: deleting it does not let anything through,
because the diff underneath fails anyway. What the check buys is the
message, which names the `sed` that stopped matching instead of printing
nine lines of difference.

One question the sweep does not answer, worth stating because a sibling
repository took an oracle's exit status for agreement and counted an oracle
that read nothing as one that agreed: can a comparison here tell "openssl
said the same thing" from "openssl said nothing"? In `agree()` it can, and
the probe above is what holds it. The trust-store loop does not go through
`agree()`, and there the answer rests on a measurement rather than on a
check. `openssl asn1parse` writes `Error in encoding` to *stdout* for input
it refuses, and prints nothing at all only for an empty file, which that loop
cannot contain: every file in it was written by `openssl x509 -outform DER`
from a certificate openssl had just read. So two empty outputs comparing
equal is unreachable there, and the backstop if it ever were not is the floor
of 5,000 elements, which a loop comparing nothing cannot clear. No check was
added for it, because a check nobody can watch fail is the thing this section
is about.

Eight survive, in two classes, and neither is a hole a harness can close
from the inside.

Three are `agree()`'s own guards taken one at a time: the check on derx's
exit status, the check on openssl's, and the check that the oracle printed
something. Each is masked by the other two and by the `cmp`, so no single
deletion changes any verdict. The reason is specific and worth writing
down: openssl prints `Error in encoding` on *stdout* for most of what it
refuses, so for a malformed input the diff fails on its own. The empty file
is the only input here where both programs print nothing at all, which makes
it the only probe that can see those three checks missing, and it takes all
three before it does. The branch for "openssl refused it and derx did not"
cannot be reached by any input at all: it needs a file `derx` accepts and
openssl rejects, and the fuzzer measures that set as empty over 10,000
mutants.

Five are floors and ceilings weakened: the corpus floor of 5,000 elements
dropped to 0, the floor of 100 certificates dropped to 0,
`basicConstraints`'s agreement floor dropped to 0, the fuzzer's
`--min-compared` dropped from 250 to 0, and `handcert`'s check that `derx`
can parse each template it builds. A floor that has been lowered cannot be
caught by the run that passes it, since the measured value still clears it;
what defends those is that every one of them prints its measured value next
to the floor, so the number is in the output whether or not it is being
judged. `handcert`'s self-check is the odd one out: it survives because all 40
templates it builds parse today, and it is there for the next one that does
not.

Two numbers in the commit messages are wrong and are corrected here,
not rewritten there. Commit 08 says twenty-eight mutations against the certificate
reader where twenty-six actually applied, two were no-ops, because the text
they targeted had already moved, and it says four survived where six did; it
names four in its own list and then describes the fifth and sixth as "changes
the sweep forced", the same fact told twice and counted once.

## Design

One file, `derx.c`, 1392 lines, 372 of them comment-only: 28% of the non-blank
lines, not the "well over half" this used to claim, explaining why openssl
does something rather than what the code does.

```
slurp  ->  hdr()  ->  walk()           derx parse
                  ->  Rd cursor  ->  cmd_cert()
```

Four decisions worth naming:

`hdr()` takes the end of the enclosing element, not of the file. It is the
only bounds argument in the program. An element whose length runs past its
parent is an error at the point of decode, not a read that lands in a
sibling and produces plausible nonsense, and there is exactly one place to get
that check right.

Every DER restriction lives in `hdr()` or in a shared checker. A reader
that is strict about indefinite lengths in one function and lax about
non-minimal integers in another is strict nowhere, because the lax path is the
one hostile input takes. `int_check()` is shared by all three places an
INTEGER's content is read. That is what makes `derx cert` exactly as strict as
`derx parse`. It was not, until a mutation pointed it out.

One rejection path. `die()` is the only way out of a bad input, status 1
with a line on stderr. Two ways out would give the harness two things to
confuse with a crash, and the entire robustness claim is that "refused" and
"crashed" stay distinguishable from outside.

OID arcs accumulate as decimal digits, not into a `uint64_t`. Not defensive
programming: openssl uses a BIGNUM and `1.2.2361183241434822606848` is a legal
OID, so a 64-bit accumulator does not fail on it, it silently prints a
different OID.

## License

GPL-3.0, matching openssl's own GPL-compatible siblings in this set and the
other seventeen repositories here. See `LICENSE`.
