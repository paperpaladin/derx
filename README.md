# derx

An ASN.1 DER reader and X.509 certificate printer in one C11 file, written to
be checked against `openssl` rather than against my own reading of X.690.

```
derx parse FILE    the DER structure: offset, depth, header length, length,
                   constructed/primitive, tag, value
derx cert  FILE    X.509 certificate fields
```

`FILE` of `-` reads stdin. Input is DER; there is no base64 decoder here, so a
PEM file has to go through `openssl x509 -outform DER` first.

## Build

```
make          # derx
make test
make test-asan
make clean
```

Pure C11, gcc, no libraries -- not even zlib. `openssl` is called by the test
harness and never by `derx`.

## The oracle

`openssl` 3.5.7 decides whether `derx` read the bytes correctly. Nothing in
`t/run.sh` is an expected value I wrote down.

The main assertion is as strong as an assertion gets, because it is a diff:

```
derx parse FILE   ==   openssl asn1parse -i -in FILE -inform DER
```

byte for byte, on anything that is valid DER. That was the first design
decision and it shaped everything else -- the column layout, the tag names,
the value formats are openssl's, down to the trailing blanks on a line with no
value, so there is no normalisation step in the middle that could be wrong in
a way that hides a disagreement.

Currently **10,822 DER elements** compare identically, of which 9,627 come
from the 150 distinct certificates in `/etc/ssl/certs`.

`derx cert` is judged by three different openssl subcommands. Five of its nine
fields are free: `openssl x509 -noout -serial -issuer -subject -startdate
-enddate` prints lines beginning `serial=`, `issuer=`, `subject=`,
`notBefore=` and `notAfter=`, so `derx cert` uses those exact spellings and
the comparison is again a plain diff. The other four -- version, signature
algorithm, key algorithm, key size -- have no one-line flag and come out of
`-text`. Extension values are checked one at a time against
`openssl x509 -ext NAME`.

Names are printed per `-nameopt RFC2253` rather than openssl's default output.
Not because it is prettier: RFC 2253 is a published document whose escaping
rules can be implemented from the text, where matching openssl's default would
be imitating one program's habits.

### Ranked, least controlled first

1. **`/etc/ssl/certs`.** 150 real certificates issued by real CAs over
   twenty-five years, read-only. They carry encoder habits nothing generated
   locally reproduces: a T61String in Entrust's 1999 root, a GeneralizedTime in
   Certum's 2011 one, OIDs openssl itself cannot name and prints in dotted
   form, an authority key identifier carrying a full issuer name and serial.
2. **Objects from openssl's own encoder.** RSA at 1024, 2048 and 3072 bits
   against SHA-1, SHA-256 and SHA-512; EC on P-256, P-384 and P-521; Ed25519;
   a `notAfter` past 2049, which forces a GeneralizedTime and so puts two
   different time encodings in one certificate; a subject carrying all 24
   X.520 attribute types; names with an embedded comma, with leading and
   trailing spaces, and a multi-valued RDN; SAN, EKU and basic constraints.
   Then five shapes a certificate never has: a PKCS#10 request, a PKCS#1
   private key whose nine INTEGERs are the widest in the suite, a PKCS#8
   PrivateKeyInfo for the long hex-dump path, an EC private key, and EC
   parameters, which are a bare OID with no SEQUENCE around them.
3. **Hand-built DER, byte by byte.** The tag-name table for all 31 universal
   tags, the three other tag classes, the high-tag-number form, every INTEGER
   sign boundary, and a complete v1 certificate with an attribute type openssl
   cannot name and a 16-bit RSA modulus. This group exists because openssl's
   generator will not emit any of it, and every one of these is a live code
   path. The certificate template has knobs for the commonName value, the
   validity, the modulus, the extensions and the unique identifiers.
4. **Malformed input, where both programs refuse.** Truncation at every
   boundary, a child overrunning its parent, a length declaring two gigabytes,
   nesting 4000 deep, a tag number too wide to represent.
5. **Valid BER that is not valid DER, where openssl accepts and `derx`
   refuses.** Each of these asserts openssl's exit 0 as well, so "openssl is
   more permissive here" stays a measured fact rather than a claim in this
   file. The list is in [What derx refuses that openssl
   accepts](#what-derx-refuses-that-openssl-accepts).
6. **Two sweeps openssl cannot judge.** Every prefix of a real certificate
   (508 inputs) and every single-byte corruption to `00` and to `FF` at every
   offset (1016 inputs), asserting only that the exit status stays at or below
   2 -- never a signal, never a sanitizer abort. openssl has an opinion about
   what bytes mean; it has none about whether we read outside them.

### `make test`

```
oracle: OpenSSL 3.5.7 9 Jun 2026 (Library: OpenSSL 3.5.7 9 Jun 2026)
under test: ./derx

ok    tag 0: the name openssl prints
...
ok    tag 30: the name openssl prints
ok    application class, primitive
ok    high tag number, universal 129
ok    INTEGER -512, kept zero byte
ok    INTEGER -65535, dropped zero byte
ok    OCTET STRING 0x7f is not printable
ok    OID 2.999, not 26.39
ok    OID arc wider than 64 bits
ok    cert: rsa2048-sha256
...
ok    system trust store: 150 certificates converted to DER
ok    /etc/ssl/certs: 9627 elements byte-identical to asn1parse
ok    cert fields: hand-built v1, unknown attribute OID, 16-bit key
ok    cert fields: T61String byte 0xC1 is Latin-1, not T.61
ok    cert fields: UTCTime 49 is 2049 and 50 is 1950
ok    cert fields: key usage with a nonzero unused bit
ok    cert fields: issuerUniqueID and subjectUniqueID are skipped
ok    cert fields: 150 certificates, 9 fields and every extension name
ok    cert extension values: 477 agree, 6 declined as not decoded
ok    truncated: content short by exactly one byte
ok    child short by one byte reads into its sibling
ok    nesting 128 deep, accepted by both
ok    nesting 129 deep, refused by both
ok    indefinite length (BER only)
ok    constructed OCTET STRING (BER segmenting)
ok    truncation sweep: every prefix of a certificate (508 inputs)
ok    single-byte corruption sweep: 00 and FF at every offset (1016 inputs)
ok    stdin arriving one byte at a time reads the same

216 passed, 0 failed, 0 skipped
10822 DER elements compared against openssl asn1parse
```

`make test-asan` runs the identical suite under
`-fsanitize=address,undefined`, including both sweeps, in under a minute.
`ASAN_OPTIONS=exitcode=86` is load-bearing and not decoration: a sanitizer
abort exits 1 by default, the suite asserts exit 1 for "cleanly refused this
input", and without the override a heap overflow would have scored as a
correct diagnostic. That collision is a defect `inflate` found the hard way in
this same set of repositories, and the number is copied from there.

If `openssl` is not on `PATH`, `t/run.sh` exits 2 rather than reporting skips.
Every expected value comes from it, so without it the suite would be comparing
`derx` to `derx` -- which is not a weaker pass, it is not a pass.

## What works

- Definite-length DER, all four tag classes, the high-tag-number form, nesting
  to openssl's own limit of 128.
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
  critical flag is still printed and still checked; only its value is not
  decoded.
- Every malformed input is refused with a diagnostic on stderr and exit 1.
  Exit 2 is reserved for a usage error. Nothing reads or writes out of bounds,
  under ASan and UBSan, across 1524 mutated inputs.

## What does **not** work

This is the half of the document that matters.

### ASN.1 that derx does not handle

- **No indefinite lengths**, which means no BER. This is deliberate -- it is
  the first thing DER removes -- but it also means `derx` cannot read a CMS or
  PKCS#7 blob produced by a streaming encoder, which is a real and common
  shape. openssl reads those and prints `l=inf`.
- **No constructed strings.** BER lets an OCTET STRING travel as a sequence of
  segments; DER does not, so `derx` refuses it. Same reasoning, same
  consequence: a legitimate BER file is unreadable.
- **No REAL, no EXTERNAL, no EMBEDDED PDV, no CHARACTER STRING, no
  RELATIVE-OID, no TIME.** Their headers are decoded and their tag names
  printed, since openssl does the same, but no content is interpreted. openssl
  prints no value for any of them either, so `derx parse` agrees -- but the
  agreement is two programs both declining, not two programs both decoding.
- **Tags 11, 13, 14, 15 and 29 are not classified** as primitive-only or
  constructed-only, where the other 26 universal tags are. openssl has no name
  for them, so the oracle has no opinion, and inventing one would be writing a
  test against my own expectation.
- **BMPString and UniversalString are decoded only inside a distinguished
  name.** In `derx parse` they print no value, which is what openssl does;
  there is no `--show-strings` mode that would decode them, because there would
  be nothing to check it against.
- **An OID arc wider than about 2^425, or an OID beyond roughly 127 arcs, is
  refused by name** rather than printed. openssl reaches for a BIGNUM and has
  no such limit. Marked `shortcut:` in the source with the upgrade path.
- **The first arc of an OID must fit in 64 bits.** Unpacking 40*X + Y needs
  arithmetic; the later arcs go through arbitrary-precision decimal and agree
  with openssl at 2^71.
- **A DER object larger than RAM cannot be parsed at all.** The whole file is
  read into one buffer. Marked `shortcut:`.
- **A distinguished name with more than 256 attributes is refused by name.**
  Marked `shortcut:`. The certificates on this machine use at most five.

### X.509 that derx does not decode

- **No cryptography of any kind.** No signature is verified, no hash is
  computed, no key is used. `derx cert` will happily print the fields of a
  certificate whose signature is four bytes of `DE AD BE EF`, and the test
  suite relies on that. **`derx` tells you what a certificate says, never
  whether it is true.** Do not make a trust decision with it.
- **No chain building, no validation, no expiry check, no name matching, no
  revocation.** It prints `notAfter`; it has no opinion about today's date.
- **Key sizes only for RSA and EC**, and for EC only the three curves the
  corpus and the fixtures contain (P-256, P-384, P-521). Any other algorithm
  prints `keybits=-`. For Ed25519 that is not a gap but the honest answer:
  openssl prints `ED25519 Public-Key:` with no bit count, so there is no number
  to agree with, and the suite asserts the absence.
- **Only the keyid-only form of the authority key identifier.** Five of the 150
  certificates here carry one with an issuer name and serial as well, which
  openssl prints on three labelled lines; the one-line-per-extension format has
  nowhere to put them, so the value prints as `?`.
- **Subject alternative name covers four of nine GeneralName kinds** --
  dNSName, iPAddress, rfc822Name, uniformResourceIdentifier. A directoryName,
  otherName, x400Address, ediPartyName or registeredID anywhere in the list
  makes the whole value print as `?`, deliberately: a partial list of the names
  a certificate is valid for is worse than no list.
- **The other extensions are names only.** CRL distribution points,
  certificate policies, authority information access, name constraints, policy
  constraints, inhibit anyPolicy, private key usage period, Netscape cert type:
  the extension's name and critical flag are printed and compared, and the
  value prints as `?`.
- **No CRLs, no PKCS#7, no PKCS#12, no OCSP, no CSR field printing.** `derx
  cert` refuses a certificate request, and the suite asserts that it does.
- **A signature algorithm's parameters are not examined.** An RSASSA-PSS
  certificate prints `sigalg=rsassaPss` and nothing about the hash or salt
  length inside the parameters, where openssl's `-text` spells all of it out.
  There is no PSS certificate in the corpus, so this is untested as well as
  unimplemented.
- **The OID table has 69 entries and is data I typed.** An OID openssl names
  and `derx` does not makes `derx parse` print digits where asn1parse prints a
  name, which fails the corpus diff. That is the intended failure mode -- loud,
  not silent -- but it does mean a certificate carrying an OID outside the
  table breaks the suite rather than degrading gracefully.

### Where derx and openssl are not comparable

- **Error messages and partial output.** When both refuse a file, only the exit
  status is compared. openssl's diagnostics and ours differ entirely, and both
  programs print the elements they managed to read before stopping, so the
  stdout of a failed parse is not compared either.
- **An input openssl refuses to read as a certificate has no cert oracle.**
  A VisibleString or an INTEGER as an attribute value makes openssl decline to
  build a name at all, so for those inputs there is nothing to compare `derx
  cert` against. `derx` refuses them too, and the suite asserts the shared
  refusal -- but that is agreement about unreadability, not about meaning.
- **`derx parse` of a key usage BIT STRING's bits.** openssl's asn1parse prints
  no value for a BIT STRING, so the bit-level decoding is only checked through
  `derx cert` and `openssl x509 -ext keyUsage`.

### What derx refuses that openssl accepts

Fourteen cases in `derx parse` and five more in `derx cert`. DER is a subset of
BER and openssl reads BER, so each of these is a second encoding of a value
that DER already has one encoding for. Each one is asserted in the suite
*including openssl's exit 0*, so the divergence is measured rather than
described:

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
| constructed OCTET STRING | read and descended | refused |
| high tag number padded with a zero septet | read | refused |
| high tag number form used for a tag below 31 | read | refused |
| SEQUENCE or BIT STRING as an attribute value | dumped as hex | refused |
| `critical FALSE` encoded explicitly | read as not critical | refused |
| a modulus with two leading zero bytes | padding ignored | refused |
| a NULL after the certificate | first object taken | refused |

The last group is the one worth defending. `derx` is narrower than openssl
about distinguished names on purpose: it never prints a name openssl would have
refused to read, which is the safe direction for a tool whose output somebody
might compare against something.

## Where the tests are still weak

- **No fuzzer.** The corruption sweep is 00 and FF at every offset of one
  certificate, which is systematic but shallow -- it never produces a
  *structurally valid* file that is semantically strange. A coverage-guided
  fuzzer against `openssl asn1parse` as a differential oracle is the obvious
  next step and is item 1 in `PLAN.md`.
- **The deep-nesting limit is tested at 128, 129 and 4000, not at the stack.**
  4000 levels is refused by the depth check, which means the recursion itself
  has never been pushed to where it would actually break. It cannot be, while
  the check is there -- which is the point, but it does mean the claim is
  "the check works", not "the recursion is safe without it".
- **One mutation survives and should not be chased.** Deleting the leading-zero
  scan from `int_bits()` leaves all 216 assertions green, and it is provably
  equivalent on anything `derx` will read. A minimal INTEGER has at most one
  leading zero byte, and only when the next byte has its high bit set; in that
  case the version with the scan computes `(n-2)*8 + 8` and the version without
  computes `(n-1)*8 + 0`, because the bit-counting loop contributes nothing for
  a zero top byte. The two differ only on a second pad byte, which X.690 8.3.2
  forbids and which `int_check()` refuses before `int_bits()` ever runs.
- **No oracle for an unknown attribute type with a non-string value.** openssl
  dumps it as hex and `derx` refuses it; a *known* attribute type with a string
  value under an unnamed OID is covered by the hand-built fixture, but the
  cross product is not.
- **The extension-value group across the corpus allows declines**, because six
  of the 483 extension values genuinely cannot be represented on one line. The
  guard against that becoming vacuous is a floor on the number of agreements
  (477 today, asserted above 400) and a ceiling on the declines (6 today,
  asserted below 20). Those are thresholds, not exact counts, and a change that
  moved twenty values from "agree" to "decline" would pass.

## On being wrong

The project's thesis is that the oracle beats my reading of the standard, and
it collected receipts:

- **openssl's tag names are not X.680's.** Tag 20 is TeletexString in the
  standard and `T61STRING` to openssl; tag 26 is VisibleString and prints as
  `VISIBLESTRING`, not the `ISO64STRING` an older openssl used. Both were wrong
  in the first draft of the table and the suite said so on the first run.
- **openssl's string conversion is not the types' own charsets.** Every
  one-byte-per-character type goes through `MBSTRING_ASC`, which treats the
  byte as a code point, so a T61String byte `0xC1` becomes U+00C1 -- Latin-1
  capital A-acute -- and not T.61's combining acute accent, which is what the
  type's charset says it is. A PrintableString byte `0xE9` gets the same
  treatment, despite `0xE9` not being in PrintableString's charset at all.
- **The 40*X+Y unpacking caps X at 2.** Without the cap, `2.999` decodes as
  `26.39`. Checked at 0.0, 0.39, 1.0, 2.0 and 2.999.
- **openssl keeps some leading zeros in a negative magnitude and drops
  others.** -512 is `FE 00` and prints as `-0200`; `FF 00 01` negates to
  `00 FF FF` and prints as `-FFFF`. One rule, two appearances, and I had
  guessed a different rule.
- **A UTCTime with no seconds is refused by openssl**, not defaulted to zero.
  That test was written as a derx-is-stricter case and reclassified.

## The harness is usually the bug

Ten of the eighteen defects recorded across these repositories were in a test
rig rather than in the code. Six of this one's were:

1. **The off-by-one the suite could not see.** Changing the content bounds
   check from `end - i < len` to `end - i + 1 < len` left all 121 assertions
   green. Every truncation fixture was short by three bytes or more, so a check
   that is off by one still caught them. Short by exactly one is the overread
   that actually happens, and the nested version of it -- where the byte past
   the child's end is its sibling's tag, inside the allocation -- is invisible
   to ASan and visible only because openssl refuses the file.
2. **The two-digit year pivot had no boundary case.** `>= 50` versus `>= 49`
   changed nothing, because openssl's own generator emits a GeneralizedTime for
   anything past 2049 and so cannot produce a certificate at the boundary.
3. **The key usage unused-bit count was dead arithmetic.** Deleting it changed
   nothing, because every key usage in the corpus has its padding bits already
   zero.
4. **The unique-identifier skip was dead code.** Deleting it changed nothing,
   because RFC 5280 tells CAs not to generate those fields and none of the 150
   certificates has one.
5. **`rd_end()`'s trailing-bytes check was dead.** Deleting it changed nothing,
   because no fixture had trailing bytes anywhere. Six do now.
6. **Two fixtures were wrong while derx was right.** The "child runs past its
   parent" case was `30 06 05 00 05 00 05 00`, a valid SEQUENCE of three
   NULLs. And the hand-built certificate's length arithmetic assumed a
   four-byte TBSCertificate header where it is three, so fifteen fixtures were
   one byte short and `derx` correctly rejected every one of them.
   `handcert()` now verifies that `derx` can parse each template it builds.

Fifty-two mutations were applied in total -- twenty-four to the DER reader,
twenty-eight to the certificate reader. Fifty-one are killed by a named
assertion; the fifty-second is the provably equivalent one above.

## Design

One file, `derx.c`, about 1340 lines, well over half of them comments
explaining why openssl does something rather than what the code does.

```
slurp  ->  hdr()  ->  walk()           derx parse
                  ->  Rd cursor  ->  cmd_cert()
```

Four decisions worth naming:

**`hdr()` takes the end of the enclosing element, not of the file.** It is the
only bounds argument in the program. An element whose length runs past its
parent is an error at the point of decode rather than a read that lands in a
sibling and produces plausible nonsense, and there is exactly one place to get
that check right.

**Every DER restriction lives in `hdr()` or in a shared checker.** A reader
that is strict about indefinite lengths in one function and lax about
non-minimal integers in another is strict nowhere, because the lax path is the
one hostile input takes. `int_check()` is shared by all three places an
INTEGER's content is read, which is what makes `derx cert` exactly as strict as
`derx parse` -- it was not, until a mutation pointed it out.

**One rejection path.** `die()` is the only way out of a bad input, status 1
with a line on stderr. Two ways out would give the harness two things to
confuse with a crash, and the entire robustness claim is that "refused" and
"crashed" stay distinguishable from outside.

**OID arcs accumulate as decimal digits, not into a `uint64_t`.** Not defensive
programming: openssl uses a BIGNUM and `1.2.2361183241434822606848` is a legal
OID, so a 64-bit accumulator does not fail on it, it silently prints a
different OID.

## License

GPL-3.0, matching openssl's own GPL-compatible siblings in this set and the
other seventeen repositories here. See `LICENSE`.
